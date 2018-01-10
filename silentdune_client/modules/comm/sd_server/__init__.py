#
# Authors: Robert Abram <robert.abram@entpack.com>,
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

import hashlib
import logging
import platform
import socket
import sys
import time
from random import random

import pkg_resources
import requests
from silentdune_client.builders import iptables as ipt
from silentdune_client.models.global_preferences import GlobalPreferences
from silentdune_client.models.node import Node, NodeBundle
from silentdune_client.modules import BaseModule
from silentdune_client.modules import QueueTask
from silentdune_client.modules.comm.sd_server.connection import SilentDuneConnection, ConnStatus
from silentdune_client.modules.firewall.logging import SilentDuneClientLoggingModule, TASK_SUBSCRIBE_LOG_EVENTS, \
    TASK_LOG_EVENT
from silentdune_client.modules.firewall.manager import SilentDuneClientFirewallModule, \
    TASK_FIREWALL_INSERT_RULES, TASK_FIREWALL_DELETE_RULES
from silentdune_client.modules.firewall.manager.iptables_utils import create_iptables_tcp_ingress_egress_rule, \
    create_iptables_egress_ingress_rule
from silentdune_client.utils.misc import is_valid_ipv4_address, is_valid_ipv6_address

from silentdune_client.modules.firewall.manager.slots import Slots

_logger = logging.getLogger('sd-client')

TASK_SEND_SERVER_ALERT = 500

# Define the available Module classes.
module_list = {
    'Silent Dune Server': {
        'module': 'SilentDuneServerModule',
    },
}


class SilentDuneServerModule(BaseModule):
    """ Silent Dune Server Module """

    _enabled = False

    # Module properties
    _server = ''
    _port = 0
    _no_tls = False
    _bundle_name = ''
    _user = ''
    _password = ''

    _flat_rules = None

    # Server Connection
    _sds_conn = None
    _connected = False
    _connection_start = False

    # Server objects
    _node = None
    _bundle = None
    _node_bundle = None
    _bundle_machine_subsets = None
    _globals = None

    # Timed events.
    _t_connection_retry = 0  # Timed event property for retrying connection to server.
    _t_next_check = 0  # Timed event used to calculate next time we should contact the server.

    # Random number of seconds between -30 and 30 to make sure all nodes do not
    # contact the server at the same time.
    _t_random_seconds = int((random() - 0.5) * 60.0)
    _t_check_interval = 0

    priority = 30

    # Status
    _locked = False
    _startup = True

    def __init__(self):

        self._arg_name = 'server'  # Set argparser name
        self._config_section_name = 'server_module'  # Set configuration file section name

        # Enable multi-threading
        self.wants_processing_thread = True

        self._enabled = False

        try:
            self._version = pkg_resources.get_distribution(__name__).version
        except:
            self._version = 'unknown'

    def add_installer_arguments(self, parser):
        """
        Virtual Override
        Add our module's argparser arguments
        """

        # Create a argument group for our module
        group = parser.add_argument_group('server module', 'Silent Dune Server module')

        group.add_argument('--server-mod-enable', action='store_true', help=_('Enable the server module'))  # noqa

        group.add_argument(_('--server'), help=_('Silent Dune server network address (required)'),  # noqa
                        default=None, type=str, metavar='IP')  # noqa
        group.add_argument(_('--server-bundle'), help=_('Firewall bundle to use for this node (required)'),  # noqa
                        default=None, type=str, metavar='BUNDLE')  # noqa
        group.add_argument(_('--server-user'), help=_('Server admin user name (required)'),  # noqa
                        default=None, type=str, metavar='USER')  # noqa
        group.add_argument(_('--server-password'), help=_('Server admin password (required)'),  # noqa
                        default=None, type=str, metavar='PASSWORD')  # noqa
        group.add_argument(_('--server-no-tls'), help=_('Do not use a TLS connection'),  # noqa
                        default=False, action='store_true')  # noqa
        group.add_argument(_('--server-port'), help=_('Use alternate http port'),  # noqa
                        default=0, type=int, metavar='PORT')  # noqa

    def validate_arguments(self, args):
        """
        Virtual Override
        Validate command line arguments and save values to our configuration object.
        :param args: An argparse object.
        """
        # See if we have been enabled or not
        if '--server-mod-enable' not in sys.argv:
            return True

        if args.server_mod_enable:
            self._enabled = True

        if not args.server:
            print('sdc-install: argument --server is required.')
            return False
        if not args.server_bundle:
            print('sdc-install: argument --server-bundle is required.')
            return False
        if not args.server_user:
            print('sdc-install: argument --server-user is required.')
            return False
        if not args.server_password:
            print('sdc-install: argument --server-password is required.')
            return False

        # Check for valid IPv4 address
        if '.' in args.server:
            if not is_valid_ipv4_address(args.server):
                print('sdc-install: argument --server is invalid ip address')
                return False

        # Check for valid IPv6 address
        if ':' in args.server:
            if not is_valid_ipv6_address(args.server):
                print('sdc-install: argument --server is invalid ip address')
                return False

        self._server = args.server
        self._port = args.server_port
        self._no_tls = args.server_no_tls
        self._bundle_name = args.server_bundle

        # User and password are only used during the install process
        self._user = args.server_user
        self._password = args.server_password

        return True

    def validate_config(self, config):
        """
        Virtual Override
        Validate configuration file arguments and save values to our config object.
        :param config: A ConfigParser object.
        """
        # See if we are enabled or not
        try:
            self._enabled = True if config.get(self._config_section_name, 'enabled').lower() == 'yes' else False
        except:
            _logger.debug('{0} configuration section not found in configuration file.'.format(
                self._config_section_name))
            self._enabled = False

        # Only worry about the rest of the configuration items if we are enabled.
        if self._enabled:

            server = config.get(self._config_section_name, 'server')

            # Check for valid IPv4 address
            if '.' in server:
                if not is_valid_ipv4_address(server):
                    _logger.error('{0}: Config value for "server" is invalid ip address'.format(self.get_name()))
                    return False

            # Check for valid IPv6 address
            if ':' in server:
                if not is_valid_ipv6_address(server):
                    _logger.error('{0}: Config value for "server" is invalid ip address'.format(self.get_name()))
                    return False

            self._server = config.get(self._config_section_name, 'server')
            self._no_tls = False if config.get(self._config_section_name, 'use_tls').lower() == 'yes' else True

            # Make sure the port value is an integer and in range
            try:
                self._port = int(config.get(self._config_section_name, 'port'))
                if not (1 < self._port <= 65536):
                    _logger.error('{0}: port value out of range ({1})'.format(self.get_name(), self._port))
            except ValueError:
                self._port = 80 if self._no_tls else 443

            self._bundle_name = config.get(self._config_section_name, 'bundle')

        return True

    def prepare_config(self, config):
        """
        Virtual Override
        Return the configuration file structure. Any new configuration items should be added here.
        Note: The order should be reverse of the expected order in the configuration file.
        """

        config.set(self._config_section_name, 'enabled', 'yes' if self._enabled else 'no')
        config.set(self._config_section_name, 'server', self._server)
        config.set(self._config_section_name, 'port', self._port)
        config.set(self._config_section_name, 'use_tls', 'no' if self._no_tls else 'yes')
        config.set(self._config_section_name, 'bundle', self._bundle_name)

        config.set_comment(self._config_section_name, self._config_section_name,
                           _('; Silent Dune Server Module Configuration\n'))  # noqa
        config.set_comment(self._config_section_name, 'server',
                           _('; The Silent Dune management server to connect with.\n'))  # noqa
        config.set_comment(self._config_section_name, 'port',
                           _('; The port used by the management server. If no port is given this\n'  # noqa
                            '; node will use port 80 or 443 to connect to the management server\n'
                            '; depending on if the --no-tls option was used during the install.\n'))
        config.set_comment(self._config_section_name, 'use_tls',
                           _('; Use a secure connection when communicating with the management server.'))  # noqa
        config.set_comment(self._config_section_name, 'bundle',
                           _('; Name of the Bundle assigned to this node. Changing this value has\n'  # noqa
                             '; no affect. The client always uses the bundle information assigned\n'
                             '; by the server.'))

        return True

    def install_module(self):
        """
        Virtual Override
        Register and download our bundle information from the server.
        """

        if not self._enabled:
            return True

        self._sds_conn = SilentDuneConnection(self._server, self._no_tls, self._port)

        if not self._sds_conn.connect_with_password(self._user, self._password):
            return False

        self.get_global_preferences()

        if not self._register_node():
            return False

        if not self._get_rule_bundle():
            return False

        if not self._set_node_bundle():
            return False

        # TODO: Get and Upload adapter interface list to server
        # Note: It might be better to call ifconfig instead of using netifaces to get adapter info.

        # self._write_bundleset_to_file()

        return True

    def service_connect_to_server(self):
        """
        Attempt to connect to the silent dune server.
        :return:
        """

        self._connected = False
        self._connection_start = False

        self._sds_conn = SilentDuneConnection(self._server, self._no_tls, self._port)
        _logger.info('{0}: Server -> {1}:{2} use-tls: {3}'.format(
            self.get_name(), self._server, self._port, not self._no_tls))

        if self._sds_conn.connect_with_machine_id(self.node_info.machine_id):
            self._connected = True
            self._connection_start = True
            self._node, status_code = self._sds_conn.get_node_by_machine_id(self.node_info.machine_id)

            if self._node:
                self._t_check_interval = (self._node.polling_interval * 60) + self._t_random_seconds
            else:
                _logger.critical('{0}: !!! node information retrieval failed'.format(self.get_name()))
        else:
            # Check to see if
            _logger.warning('{0}: Failed to connect with server, will attempt reconnection.'.format(self.get_name()))

        return self._connected

    def service_startup(self):
        _logger.debug('{0}: module startup called'.format(self.get_name()))

        return True

    def service_shutdown(self):
        _logger.debug('{0}: module shutdown called'.format(self.get_name()))

        # Notify the server we are no longer active.
        if self._connected:
            self.update_server_node_info(active=False)

        return True

    def _add_server_access_rule(self):
        """
        Add a management server connection rule so we can connect
        :return:
        """

        rule = create_iptables_egress_ingress_rule(
            self._server, self._port, 'tcp', Slots.silentdune_server, transport=ipt.TRANSPORT_AUTO)

        # Notify the firewall module to reload the rules.
        task = QueueTask(TASK_FIREWALL_INSERT_RULES,
                         src_module=self.get_name(),
                         dest_module=SilentDuneClientFirewallModule().get_name(),
                         data=rule)
        self.send_parent_task(task)

    def process_loop(self):

        if self._startup:
            self._startup = False

            self._add_server_access_rule()
            time.sleep(3)  # Give the firewall time to add the rules before we attempt to connect

            self.service_connect_to_server()

            if self._sds_conn.status == ConnStatus.not_registered:
                _logger.error('{0} this node is not registered, unable to download rules'.format(self.get_name()))

        # If we are not registered, just return
        if self._sds_conn and self._sds_conn.status == ConnStatus.not_registered:
            return

        # If we are not connected to the server, try reconnecting every 60 seconds.
        if not self._connected:
            if self.timed_event('_t_connection_retry', 60):
                self._t_connection_retry = self.t_seconds
                self.service_connect_to_server()

        if self._connected:

            # Check to see if the connection to the server has just started.
            if self._connection_start:

                # Get the global preferences
                self.get_global_preferences()

                # Notify the server we are active now.
                self._node.active = True
                self.update_server_node_info(active=True)

                # Set our lock down mode value.
                self.set_lockdown_mode()

                # Update our firewall with rules from the server.
                self.update_node_firewall_rules_from_server()

                self._connection_start = False

                # Subscribe to log events
                task = QueueTask(TASK_SUBSCRIBE_LOG_EVENTS,
                                 src_module=self.get_name(),
                                 dest_module=SilentDuneClientLoggingModule().get_name())
                self.send_parent_task(task)

                _logger.debug('Next server check in {0} seconds.'.format(self._t_check_interval))

            # Check to see if the node rule bundle information has changed.
            if self.timed_event('_t_next_check', self._t_check_interval):
                _logger.debug('Next server check in {0} seconds.'.format(self._t_check_interval))

                self._node, status_code = self._sds_conn.get_node_by_machine_id(self.node_info.machine_id)

                # Check to see if we need to update our firewall rules bundle.
                if self._node.sync:
                    _logger.info('{0}: Found signal to update the firewall rules bundle.'.format(self.get_name()))

                    self.set_lockdown_mode()
                    self.update_node_firewall_rules_from_server()

                    # Update our information with the server.
                    self.update_server_node_info(sync=False)

    def process_task(self, task):

        if task:
            t_id = task.get_task_id()

            if t_id == TASK_LOG_EVENT:
                _logger.debug('{0}: received log event.'.format(self.get_name()))
                if self.node_info.platform == 'linux':

                    data = task.get_data()  # IPLogEvent object
                    data.node = self._node.id
                    self._sds_conn.iptables_send_alert(data)

    def set_lockdown_mode(self):
        """
        Set the lock down mode
        :return:
        """
        # Check locked down mode.
        if not self._locked and self._node.locked:
            _logger.warning('System is now in lock down mode.')
            self._locked = True

        if self._locked and not self._node.locked:
            _logger.warning('System is no longer in lock down mode.')
            self._locked = False

    def get_global_preferences(self):

        self._globals, status_code = self._sds_conn.get_global_preferences()

        if not globals or status_code != requests.codes.ok:
            _logger.error('Failed to download global preferences. Err: {0}'.format(status_code))
            self._globals = GlobalPreferences(lockdown_slot_level=120)
            return False

        return True

    def update_server_node_info(self, **kwargs):

        # _logger.debug(self._node.to_json())

        data = {u'machine_id': self._node.machine_id}  # machine_id is always required to update a node data record.

        if 'sync' in kwargs:
            data[u'sync'] = kwargs['sync']
            self._node.sync = kwargs['sync']

        if 'active' in kwargs:
            self._node.active = kwargs['active']
            data[u'active'] = kwargs['active']
        else:
            data[u'active'] = self._node.active

        reply, status_code = self._sds_conn.update_node(self._node.id, data)

        # _logger.debug(self._node.to_json())

        if not self._node or status_code != requests.codes.ok:
            _logger.error('{0}: Failed to update node information.'.format(self.get_name()))
            return False

        return True

    def update_node_firewall_rules_from_server(self):
        """
        Retrieve the node bundle rules from the server and send them to the Firewall module.
        :return:
        """

        # TODO: Save current bundle machine subsets and then look for any orphaned sets and remove them
        # from the firewall.

        if self._bundle_machine_subsets:
            # Until the orphan rule check is in place, just tell the firewall to delete all rules.
            task = QueueTask(TASK_FIREWALL_DELETE_RULES,
                             src_module=self.get_name(),
                             dest_module=SilentDuneClientFirewallModule().get_name(),
                             data=self._bundle_machine_subsets)
            self.send_parent_task(task)

        # Get updated bundle information.
        self._node_bundle, status_code = self._sds_conn.get_node_bundle_by_node_id(self._node.id)
        self._bundle, status_code = self._sds_conn.get_bundle_by_id(self._node_bundle.bundle)

        if not self._download_bundleset():
            if self._sds_conn.request_error:
                _logger.error('{0}: request to server failed, changing state to not connected'.format(self.get_name()))
                self._connected = False
                return False

        if self._bundle_machine_subsets and len(self._bundle_machine_subsets) > 0:

            rules = self.flatten_rules(self._bundle_machine_subsets)

            # Check to see if we are in lockdown mode. If so filter out all
            if self._locked:
                data = list()
                for i in rules:
                    if i.slot <= self._globals.lockdown_slot_level or i.slot >= self._globals.rejection_slot_level:
                        data.append(i)
            else:
                data = rules

            # Notify the firewall module to reload the rules.
            task = QueueTask(TASK_FIREWALL_INSERT_RULES,
                             src_module=self.get_name(),
                             dest_module=SilentDuneClientFirewallModule().get_name(),
                             data=data)
            self.send_parent_task(task)

            # Notify the firewall module to reload the rules.
            # task = QueueTask(TASK_FIREWALL_RELOAD_RULES,
            #                  src_module=self.get_name(),
            #                  dest_module=SilentDuneClientFirewallModule().get_name())
            # self.send_parent_task(task)

            # Reset the node rule bundle check timer
            self._t_next_check = self.t_seconds

        else:
            _logger.error('{0}: No rules downloaded from server, unable to update firewall module.'.format(
                self.get_name()))
            return False

        return True

        # TODO: Port knocker event triggers.  https://github.com/moxie0/knockknock

        # Every 10 seconds, send the firewall module a QueueTask
        # if self._seconds_t > self._event_t and self._seconds_t % 4 == 0.0:
        #     self._event_t = self._seconds_t
        #
        #     _logger.debug('Sending {0} module a task.'.format(type(SilentDuneClientFirewallModule).__name__))
        #
        #     task = QueueTask(TASK_FIREWALL_RELOAD_RULES,
        #                      self.get_name(),
        #                      SilentDuneClientFirewallModule().get_name(),
        #                      None)
        #
        #     self.send_parent_task(task)

    def _register_node(self):
        """
        Contact the server to register this node with the server.
        """
        # Look for existing Node record.
        self._node, status_code = self._sds_conn.get_node_by_machine_id(self.node_info.machine_id)

        if status_code == requests.codes.ok and self._node and self._node.id:
            _logger.warning('{0}: Node already registered, using previously registered node info.'.format(
                self.get_name()))
            return True

        self.cwrite('{0}: Registering Node...  '.format(self.get_name()))

        node = Node(
            platform=self.node_info.firewall_platform,
            os=platform.system().lower(),
            dist=platform.dist()[0],
            dist_version=platform.dist()[1],
            hostname=socket.gethostname(),
            python_version=sys.version.replace('\n', ''),
            machine_id=self.node_info.machine_id,
            fernet_key='',  # Fernet.generate_key().decode('UTF-8'),
            polling_interval=self._globals.polling_interval
        )

        # Attempt to register this node on the SD server.
        self._node, status_code = self._sds_conn.register_node(node)

        if status_code != requests.codes.created or not self._node or self._node.id is None:
            self.cwriteline('[Failed]', 'Register Node failed, unknown reason.')
            return False

        self.cwriteline('[OK]', 'Node successfully registered.')

        return True

    def _get_rule_bundle(self):

        if self._bundle_name:

            self.cwrite('Looking up rule bundle...')

            self._bundle, status_code = self._sds_conn.get_bundle_by_name(self._bundle_name)

            if self._bundle and self._bundle.id > 0:
                self.cwriteline('[OK]', 'Found rule bundle.')
                return True

            self.cwriteline('[Failed]', 'Unable to find rule bundle named "{0}".'.format(self._bundle_name))

            # _logger.warning(_("Unable to find the rule bundle specified. The installer can try to lookup "  # noqa
            #                   "and use the default server rule bundle."))  # noqa
            #
            # self.cwrite(_('Do you want to use the server default rule bundle? [y/N]:'))  # noqa
            # result = sys.stdin.read(1)
            #
            # if result not in {'y', 'Y'}:
            #     _logger.debug('User aborting installation process.')
            #     return False

        self.cwrite('Looking up the server default rule bundle...')

        self._bundle, status_code = self._sds_conn.get_default_bundle()

        if not self._bundle or self._bundle.id is None:
            self.cwriteline('[Failed]', 'Default bundle lookup failed.')
            return False

        self.cwriteline('[OK]', 'Found default rule bundle.')

        return True

    def _set_node_bundle(self):

        self.cwrite('Setting Node rule bundle...')

        data = NodeBundle(node=self._node.id, bundle=self._bundle.id)

        self._node_bundle, status_code = self._sds_conn.create_node_bundle(data)

        if not self._node_bundle:
            self.cwriteline('[Failed]', 'Unable to set Node rule bundle.')
            return False

        self.cwriteline('[OK]', 'Node rule bundle successfully set.')
        return True

    def _download_bundleset(self):

        # Get the machineset IDs assigned to the bundle
        self._bundle_machine_subsets, status_code = self._sds_conn.get_bundle_machine_subsets(self._node_bundle)

        if status_code == requests.codes.ok:
            if self._bundle_machine_subsets is None:
                _logger.warning('{0}: no rules found in bundle'.format(self.get_name()))

            return True

        _logger.error('{0}: failed to download rule bundle from server ({1})'.format(self.get_name(), status_code))
        return False

    def flatten_rules(self, obj, level=0):
        """
        Takes nested rules and recursively un-winds them.
        :param obj: Rules object
        :param level: recursion level counter
        :return: rule list
        """

        if level == 0:
            self._flat_rules = list()

        try:

            # Test obj to see if it is really a rule
            if obj.to_json().encode('utf-8'):

                match = False

                for rule in self._flat_rules:
                    if hashlib.sha1(rule.to_json().encode('utf-8')).hexdigest() == \
                            hashlib.sha1(obj.to_json().encode('utf-8')).hexdigest():
                        match = True

                # Don't add rules that already exist in our flat list.
                if not match:
                    self._flat_rules.append(obj)

        except AttributeError:
            if obj and len(obj) > 0:
                for o in obj:
                    self.flatten_rules(o, (level+1))

        if level == 0:
            rules = self._flat_rules
            self._flat_rules = None  # clear list.
            return rules