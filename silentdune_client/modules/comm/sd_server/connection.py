#
# Authors: Robert Abram <robert.abram@entpack.com>
#
# Copyright (C) 2015-2017 EntPack
# see file 'LICENSE' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from enum import IntEnum
import logging
import requests
import socket


from silentdune_client.models.iptables_rules import IPMachineSubset, Bundle
from silentdune_client.models.node import Node, NodeBundle
from silentdune_client.models.global_preferences import GlobalPreferences
from silentdune_client.utils.console import ConsoleBase

_logger = logging.getLogger('sd-client')


class ConnStatus(IntEnum):

    unknown = 1
    authenticated = 2
    not_registered = 3


class SilentDuneConnection (ConsoleBase):

    # Server Authentication
    _oauth_crypt_token = None  # Fernet Encrypted oauth2 information
    _machine_id = None  # Machine id to use for authentication
    _cookies = None

    status = ConnStatus.unknown

    # Connection Information
    _server = None
    _base_url = None
    _no_tls = False
    _port = -1
    _user = None
    _password = None
    _ip = None

    request_error = False

    def __init__(self, server, no_tls, port):

        self._server = server
        self._no_tls = no_tls
        self._port = port

    def _build_base_url(self):

        # Build base URL
        self._base_url = 'http://' if self._no_tls else 'https://'
        self._base_url += self._server
        self._base_url += '' if self._port == -1 else ':{0}'.format(self._port)

    def _set_authentication(self):
        """
        Set the server Authentication information for each request.  During the install process, oauth2 authentication
        is used in a cookie. While the service is running, machine_id authentication is used in a request header.
        :return:
        """

        if self._machine_id:
            return {'node': self._machine_id}, None

        if self._oauth_crypt_token:
            return None, dict(token=self._oauth_crypt_token)

        return None, None

    def _make_json_request(self, reqtype, url, data=None):

        reply = None
        status_code = None
        rq = None

        self.request_error = False

        if not self.status == ConnStatus.authenticated:
            _logger.error('Not authenticated to SD server.')
            return reply, status_code, rq

        try:

            self._build_base_url()
            u = '{0}{1}'.format(self._base_url, url)

            # Set the server authentication method.
            headers, cookies = self._set_authentication()

            if reqtype is 'GET':
                rq = requests.get(u, cookies=cookies, headers=headers, timeout=30)
            elif reqtype is 'POST':
                rq = requests.post(u, data=data, cookies=cookies, headers=headers, timeout=30)
            elif reqtype is 'PUT':
                rq = requests.put(u, data=data, cookies=cookies, headers=headers, timeout=30)
            elif reqtype is 'DELETE':
                rq = requests.delete(u, cookies=cookies, headers=headers, timeout=30)
            elif reqtype is 'HEAD':
                rq = requests.head(u, cookies=cookies, headers=headers, timeout=30)
            elif reqtype is 'OPTIONS':
                rq = requests.options(u, cookies=cookies, headers=headers, timeout=30)

        except requests.Timeout:
            _logger.error('Server request timeout.')
            self.request_error = True
        except requests.ConnectionError:
            _logger.error('Server connection error.')
            self.request_error = True
        except requests.RequestException:
            _logger.error('Server request failed.')
            self.request_error = True
        else:

            try:
                reply = rq.json()
            except ValueError:
                pass

            status_code = rq.status_code

        return reply, status_code, rq

    # The purpose of this method is to authenticate the user and password against the SD server and
    # retrieve the encrypted Oauth2 token.
    def connect_with_password(self, username, password):

        if not username or not password:
            _logger.error('Invalid parameter passed.')
            raise ValueError

        self.status = ConnStatus.unknown

        self.cwrite('Resolving server...  ')

        try:
            self._ip = socket.gethostbyname(self._server)
        except socket.error:
            _logger.error('Unable to resolve server ({0})'.format(self._server))
            return False

        self.cwriteline('[OK]', 'Server successfully resolved.')

        self.cwrite('Attempting to authenticate with SD server...  ')

        # Make a GET request so we can get the CSRF token.
        try:

            self._build_base_url()
            resp = requests.get('{0}/accounts/login/'.format(self._base_url))
            _logger.debug('{0}/accounts/login/'.format(self._base_url))

            if resp.status_code != requests.codes.ok:
                _logger.error('Unable to retrieve CSRF token ({0})'.format(resp.status_code))
                return False

            csrf = resp.cookies['csrftoken']

        except Exception:
            _logger.error('CSRF token request attempt failed.')
            return False

        try:

            # Make a POST authentication request to get the encrypted oauth2 token
            resp = requests.post('{0}/accounts/login/'.format(self._base_url),
                                 cookies=resp.cookies,
                                 data={'grant_type': 'password', 'username': username, 'password': password,
                                 'csrfmiddlewaretoken': csrf})

            if resp.status_code != requests.codes.ok:
                _logger.error('Unable to authenticate to server ({0})'.format(resp.status_code))
                return False

        except requests.RequestException:
            _logger.error('Authentication request attempt failed')
            return False

        if resp.json() is None:
            _logger.error('Unknown error occurred parsing server response.')

        # Convert reply into JSON
        reply = resp.json()

        # Check reply status value
        if reply['status'] != 'OK':
            _logger.error('Server authentication request failed.')
            return False

        # Save token and cookies for later use
        self._oauth_crypt_token = resp.cookies['token']
        self._cookies = resp.cookies

        self.cwriteline('[OK]', 'Successfully authenticated with server.')

        self.status = ConnStatus.authenticated

        return True

    def connect_with_machine_id(self, machine_id):
        """
        Authenticate to the server with node machine_id value.
        :return: True if connected and authenticate, otherwise false.
        """

        self.status = ConnStatus.unknown
        self._machine_id = machine_id

        try:
            self._ip = socket.gethostbyname(self._server)
        except socket.error:
            _logger.error('Unable to resolve server ({0})'.format(self._server))
            return False

        _logger.info('Attempting to authenticate with SD server.')

        try:

            self._build_base_url()
            # Reply contains dict array of Node records.  Reply array should be empty or contain one Node record.
            url = '{0}/api/nodes/?machine_id={1}'.format(self._base_url, self._machine_id)

            # Set the server authentication method.
            headers, cookies = self._set_authentication()

            resp = requests.get(url, cookies=cookies, headers=headers, timeout=30)

            if resp.status_code == requests.codes.ok:

                reply = resp.json()

                if reply is not None and reply[0]['machine_id'] == self._machine_id:
                    self.status = ConnStatus.authenticated
                    _logger.info('successfully authenticated with server.')
                    self.status = ConnStatus.authenticated
                    return True

            elif resp.status_code == requests.codes.forbidden:
                _logger.error('*** Node auth failed, we are not registered on the server.        ***')
                _logger.error('*** This node needs to be registered with the Silent Dune server. ***')
                _logger.error('*** Please run sdc-install to register.                           ***')
                self.status = ConnStatus.not_registered
            else:
                _logger.error('node auth failed, unknown code: {0}'.format(resp.status_code))

        except requests.RequestException:
            _logger.error('node authentication request attempt failed')

        return False

    def get_node_by_machine_id(self, machine_id):
        """
        Request Node object from server filtered by machine_id value.
        :param machine_id:
        :return Node object:
        """

        url = '/api/nodes/?machine_id={0}'.format(machine_id)

        # Reply contains dict array of Node records.  Reply array should be empty or contain one Node record.
        reply, status_code, rq = self._make_json_request('GET', url)

        # If we have a good code and no data, then the node has not been registered yet.
        if status_code == requests.codes.ok:
            if reply is not None and len(reply) != 0:
                return Node(reply[0]), status_code

        _logger.error('Node lookup request failed.')
        return None, status_code

    def get_global_preferences(self):
        """
        Request GlobalPreferences object from server.
        :return Node object:
        """

        url = '/api/globals/'

        # Reply contains dict array of Node records.  Reply array should be empty or contain one Node record.
        reply, status_code, rq = self._make_json_request('GET', url)

        if status_code == requests.codes.ok:
            if reply is not None and len(reply) != 0:
                return GlobalPreferences(reply[0]), status_code

        _logger.error('Global preferences lookup request failed.')
        return None, status_code

    def iptables_send_alert(self, log):
        """
        Send an IPTables system log event to the server.
        :param data: IPLogEvent object
        :return: id
        """
        child_log = None

        if log.icmp_error_header:
            child_log = log.icmp_error_header
            log.icmp_error_header = None
            log_d = log.to_dict()
        else:
            log_d = log.to_dict()

        try:
            reply, status_code, rq = self._make_json_request('POST', '/api/alerts/iptables/', log_d)

            if status_code == requests.codes.created:
                if not child_log:
                    return reply['id'], status_code

                # If we have a child record, set the parent_id and send it.
                child_log.parent_id = reply['id']
                child_d = child_log.to_dict()

                reply, status_code, rq = self._make_json_request('POST', '/api/alerts/iptables/', child_d)

                if status_code == requests.codes.created:
                    return reply['id'], status_code
        except:
            pass

        return None, requests.codes.teapot

    def register_node(self, node):
        """
        Register Node on server.
        :param node:
        :return Node:
        """
        try:
            node_d = node.to_dict()
        except AttributeError:
            _logger.critical('Node parameter is not valid in register_node method.')
            return None, requests.codes.teapot

        try:
            # Reply contains single Node record
            reply, status_code, rq = self._make_json_request('POST', '/api/nodes/', node_d)

            if reply is not None and status_code is not None:

                # 201 means the node record was created successfully.
                if status_code == requests.codes.created or status_code == requests.codes.ok:
                    return Node(reply), status_code

            _logger.debug('Register node failed ({0}).'.format(status_code))
            return None, status_code

        except:
            pass

        return None, requests.codes.teapot

    def update_node(self, node_id, data):
        """
        Update Node information on server.  Currently only "active" and "sync" fields should be updated.
        :param data: Dictionary with values for "active" and/or "sync" node fields.
        :return Node:
        """
        try:
            # Reply contains single Node record
            reply, status_code, rq = self._make_json_request('PUT', '/api/nodes/{0}/'.format(node_id), data)

            # _logger.debug('Node Update Request: {0}: {1}'.format(status_code, reply))

            if reply is not None and status_code is not None:

                # 200 means the node record was update successfully.
                if status_code == requests.codes.ok:
                    return Node(reply), status_code

            _logger.debug('Update node failed ({0}).'.format(status_code))
            return None, status_code

        except:
            # _logger.debug('ex: {0}: {1}'.format(status_code, reply))
            pass

        return None, requests.codes.teapot

    def get_node_bundle_by_node_id(self, node_id):
        """
        Get the Node Bundle from the server using the node id
        :param node_id:
        :return:
        """
        url = '/api/nodes/{0}/bundle/'.format(node_id)

        reply, status_code, rq = self._make_json_request('GET', url)

        if reply is not None and status_code == requests.codes.ok and len(reply) > 0:
            return NodeBundle(reply[0]), status_code

        _logger.error('Failed to retrieve node bundle by node id ({0}).'.format(node_id))
        return None, status_code

    def get_bundle_by_name(self, name):
        """
        Request Bundle object from server filtered by name value.
        :param name:
        :return Bundle:
        """
        url = '/api/bundles/?name={0}'.format(name)

        reply, status_code, rq = self._make_json_request('GET', url)

        if reply is not None and status_code == requests.codes.ok and len(reply) > 0:
            return Bundle(reply[0]), status_code

        _logger.error('Failed to retrieve bundle by name ({0}).'.format(name))
        return None, status_code

    def get_bundle_by_id(self, bundle_id):
        """
        Request Bundle object from server filtered by name value.
        :param name:
        :return Bundle:
        """
        url = '/api/bundles/{0}/'.format(bundle_id)

        reply, status_code, rq = self._make_json_request('GET', url)

        if reply is not None and status_code == requests.codes.ok and len(reply) > 0:
            return Bundle(reply), status_code

        _logger.error('Failed to retrieve bundle by id ({0}).'.format(bundle_id))
        return None, status_code

    def get_default_bundle(self):
        """
        Request default Bundle object from server.
        :return Bundle:
        """

        url = '/api/bundles/?default'

        # Reply contains single Bundle record
        reply, status_code, rq = self._make_json_request('GET', url)

        if reply is not None and status_code == requests.codes.ok and len(reply) > 0:
            return Bundle(reply[0]), status_code

        return None, status_code

    def create_node_bundle(self, nb):

        if nb is None:
            _logger.critical('NodeBundle parameter is not valid in create_node_bundle method.')
            return None, requests.codes.teapot

        url = '/api/nodes/{0}/bundle/'.format(nb.node)

        # NodeBundleViewSet will update or create with a POST request.
        reply, status_code, rq = self._make_json_request('POST', url, nb.to_dict())

        if reply is not None and \
                (status_code == requests.codes.created or status_code == requests.codes.ok):
            return NodeBundle(reply), status_code

        return None, status_code

    def update_node_bundle(self, nb):

        if nb is None:
            _logger.critical('NodeBundle parameter is not valid in update_node_bundle method.')
            return None, requests.codes.teapot

        url = '/api/nodes/{0}/bundle/{1}/'.format(nb.node, nb.bundle)

        # NodeBundleViewSet will update or create with a POST request.
        reply, status_code, rq = self._make_json_request('PUT', url, nb.to_dict())

        if reply is not None and \
                (status_code == requests.codes.created or status_code == requests.codes.ok):
            return NodeBundle(reply), status_code

        return None, status_code

    def get_bundle_machine_subsets(self, nb):

        if not isinstance(nb, NodeBundle):
            _logger.critical('NodeBundle parameter is not valid in create_or_update_node_bundle method.')
            return None, requests.codes.teapot

        url = '/api/bundles/{0}/machine_subsets/'.format(nb.bundle)

        # Reply contains dict array of IPMachineSet records.
        reply, status_code, rq = self._make_json_request('GET', url)

        ol = list()

        if reply is not None and status_code == requests.codes.ok:

            # Iterate over the reply to get our machine subset records.
            for o in reply:

                url = '/api/iptables/machine_subsets/{0}/'.format(o['machine_subset'])

                # Reply contains single IPMachineSubset record.
                reply, status_code, rq = self._make_json_request('GET', url)

                if reply is not None and status_code == requests.codes.ok:
                    ol.append(IPMachineSubset(reply))

        if len(ol) == 0:
            return None, status_code

        return ol, status_code

    # def write_bundle_to_file(self, path, bundle):
    #     """
    #     Write the bundle machine set data to a file.
    #     This process starts by looping through each of the iptable table names, then calling o.write_chains() to
    #     setup the custom iptables chain names for that table.  Then o.write() is called to write out the rules for
    #     that table. Chain names are defined by the built-in chain name, slot number and pk id of the IPRing object.
    #     """
    #
    #     files = list()
    #
    #     if bundle is None:
    #         _logger.error('Array of chainset objects not valid.')
    #         return files
    #
    #     # Write out machine sets to individual files with the slot number as the name.
    #     for ms in bundle:
    #         file = os.path.join(path, u'{0}.bundle'.format(ms.slot))
    #
    #         _logger.debug('Writting set {0} rules to -> {1}'.format(ms.slot, file))
    #         with open(file, 'w') as handle:
    #             handle.write('{0}\n'.format(ms.to_json()))
    #
    #     for v in {u'ipv4', u'ipv6'}:
    #
    #         file = os.path.join(path, u'{0}.rules'.format(v))
    #
    #         _logger.debug('Writting {0} rules to -> {1}'.format(v, file))
    #
    #         files.append(file)
    #
    #         writer = IPRulesFileWriter(bundle)
    #         writer.write_to_file(file, v)
    #
    #     return files
