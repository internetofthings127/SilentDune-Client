#
# Authors: Ma He <mahe.itsec@gmail.com>
#          Robert Abram <robert.abram@entpack.com>
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
import json
import logging
import os
import socket
import sys
import time

try:
    from urllib import parse
except ImportError:
    # < 3.0
    import urlparse as parse

import dns.resolver
import requests
from silentdune_client.utils.misc import is_valid_ipv4_address, is_valid_ipv6_address
from silentdune_client.builders import iptables as ipt
from silentdune_client.models.remote_config import RemoteConfig
from silentdune_client.modules import BaseModule, QueueTask
from silentdune_client.modules.firewall.manager import SilentDuneClientFirewallModule, TASK_FIREWALL_INSERT_RULES, \
    TASK_FIREWALL_DELETE_SLOT, TASK_FIREWALL_ALLOW_ALL_DNS_ACCESS, TASK_FIREWALL_DISABLE_ALL_DNS_ACCESS
from silentdune_client.modules.firewall.manager.iptables_utils import create_iptables_egress_ingress_rule, \
    create_iptables_remote_config, create_iptables_egress_rule_dest, create_iptables_ingress_rule_source
from silentdune_client.modules.firewall.manager.slots import Slots

_logger = logging.getLogger('sd-client')

module_list = {
    'Silent Dune Remote Config': {
        'module': 'SilentDuneRemoteConfigModule',
    },
}


class SilentDuneRemoteConfigModule(BaseModule):
    """Silent Dune Remote Config Module"""

    _t_check_remote_config = 0  # Timed event property for debug message loop.
    _t_reload_task = 0  # Timed event property for reloading firewall rules.

    _uri = None
    _remote_config_url = None
    _remote_config_dns_name = None
    _remote_config_check_interval = 0

    _remote_config_hash = None

    _slot_config_access = Slots.rc_access
    _slot_config_apply = Slots.rc_apply

    _startup = True

    _retry_count = 0

    priority = 90  # Low priority startup

    def __init__(self):

        self._arg_name = 'remoteconfig'  # Set argparser name
        self._config_section_name = 'remote_config'  # Set configuration file section name

        # Enable multi-threading
        self.wants_processing_thread = True

        self._enabled = False
        self._remote_config_check_interval = 4 * 3600  # 4 hours

    def add_installer_arguments(self, parser):
        """
        Virtual Override
        Add our module's argparser arguments
        """

        # Create a argument group for our module
        group = parser.add_argument_group('remote config module', 'Silent Dune Remote Config module')

        group.add_argument('--remoteconfig-mod-enable', action='store_true',  # noqa
                           help=_('Enable the remote config module'))  # noqa

        group.add_argument(_('--remote-config-url'), help=_('Set remote config url'),  # noqa
                           default=None, type=str)  # noqa
        group.add_argument(_('--remote-config-dns-name'), help=_('Remote config hash value DNS TXT field.'),  # noqa
                           default=None, type=str)  # noqa
        group.add_argument(_('--remote-config-check-interval'), help=_('Set check interval for remote config'),  # noqa
                           default=4 * 3600, type=str)  # noqa

    def validate_arguments(self, args):
        """
        Virtual Override
        Validate command line arguments and save values to our configuration object.
        :param args: An argparse object.
        """
        # See if we have been enabled or not
        if '--remoteconfig-mod-enable' not in sys.argv:
            return True

        if args.remoteconfig_mod_enable:
            self._enabled = True

        # Check for any required arguments here
        try:
            self._uri = parse.urlparse(args.remote_config_url)
        except:
            print('sdc-install: error validating remote config url ({0})'.format(args.remote_config_url))
            return False

        if not self._uri.scheme or self._uri.scheme not in ['file', 'http', 'https', 'ftp']:
            print('sdc-install: invalid protocol for remote config url ({0})'.format(self._uri.scheme))
            return False

        if self._uri.scheme == 'file':
            if not os.path.isfile(self._uri.path):
                print('sdc-install: warning: rule config file not found ({1})'.format(self.get_name(), self._uri.path))
                
        self._remote_config_url = args.remote_config_url
        self._remote_config_dns_name = args.remote_config_dns_name
        self._remote_config_check_interval = args.remote_config_check_interval

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

            self._remote_config_url = config.get(self._config_section_name, 'remote_config_url').lower()

            try:
                self._uri = parse.urlparse(self._remote_config_url)
            except:
                _logger.error('{0}: error validating remote config url ({1})'.format(self.get_name(),
                                                                                     self._remote_config_url))
                return False

            if not self._uri.scheme or self._uri.scheme not in ['file', 'http', 'https', 'ftp']:
                _logger.error('{0}: invalid protocol for remote config url ({1})'.format(self.get_name(),
                                                                                         self._uri.scheme))
                return None

            if self._uri.scheme == 'file':
                if not os.path.isfile(self._uri.path):
                    _logger.warning('{0}: rule config file not found ({1})'.format(self.get_name(), self._uri.path))

            self._remote_config_url = config.get(self._config_section_name, 'remote_config_url').lower()
            self._remote_config_dns_name = config.get(self._config_section_name, 'remote_config_dns_name').lower()
            self._remote_config_check_interval = int(
                config.get(self._config_section_name, 'remote_config_check_interval'))

        return True

    def prepare_config(self, config):
        """
        Virtual Override
        Return the configuration file structure. Any new configuration items should be added here.
        Note: The order should be reverse of the expected order in the configuration file.
        """

        config.set(self._config_section_name, 'enabled', 'yes' if self._enabled else 'no')
        config.set(self._config_section_name, 'remote_config_url',
                   self._remote_config_url if self._remote_config_url else None)
        config.set(self._config_section_name, 'remote_config_dns_name',
                   self._remote_config_dns_name if self._remote_config_dns_name else '')
        config.set(self._config_section_name, 'remote_config_check_interval',
                   self._remote_config_check_interval if self._remote_config_check_interval else 4 * 3600)

        config.set_comment(self._config_section_name, self._config_section_name,
                           _('; Silent Dune remote config Module Configuration\n'))  # noqa
        config.set_comment(self._config_section_name, 'remote_config_url',
                           _('; Remote config url.\n'))  # noqa
        config.set_comment(self._config_section_name, 'remote_config_dns_name',
                           _('; DNS TXT field to retrieve remote config hash check value.\n'))  # noqa
        config.set_comment(self._config_section_name, 'remote_config_check_interval',
                           _('; Interval in seconds to re-check remote config.\n'))  # noqa

        return True

    def service_startup(self):
        _logger.debug('{0}: module startup called'.format(self.get_name()))

        if not self.validate_config(self.config):
            _logger.error('{0}: module configuration validation failed.'.format(self.get_name()))
            return False

        if not self._enabled:
            return True

        _logger.debug(
            '{0} config: {1}: {2}: {3}'.format(self.get_name(), self._remote_config_url,
                                               self._remote_config_dns_name,
                                               self._remote_config_check_interval))

        self._retry_count = 0

        return True

    def service_shutdown(self):
        _logger.debug('{0}: module shutdown called'.format(self.get_name()))

    def process_loop(self):

        if self._startup:

            time.sleep(2)  # Sleep 2 seconds to let DNS become available

            self._retry_count += 1

            try:

                if self._uri.scheme == 'file':

                    if self.apply_remote_config():
                        self._startup = False
                        return

                else:
                    # Try resolving the config file host and setup rules
                    socket.getaddrinfo(self._uri.hostname, 80, 0, 0, socket.IPPROTO_TCP)

                    self.allow_remote_config_access()

                    if self.apply_remote_config():
                        self._startup = False
                        self._retry_count = 0
                        return
            except:
                pass

            if self._retry_count >= 10:
                if self._uri.scheme == 'file':
                    _logger.error('{0}: failed to set rules from file'.format(self.get_name()))
                else:
                    _logger.error('{0}: unable to resolve host ({1})'.format(self.get_name(), self._uri.hostname))
                    _logger.error('{0}: unable to download remote config file from host'.format(self.get_name()))

                self._startup = False
                self._retry_count = 0
                return

        if self.timed_event('_t_check_remote_config', self._remote_config_check_interval):
            self._retry_count = 0
            self._startup = True

    def allow_remote_config_access(self):

        rules = list()

        if self._uri.scheme == 'http':
            rules.append(self.get_http_rule_by_hostname())
        elif self._uri.scheme == 'https':
            rules.append(self.get_https_rule_by_hostname())
        elif self._uri.scheme == 'ftp':
            rules.append(self.get_ftp_rule_by_hostname())

        # Notify the firewall module to reload the rules.
        task = QueueTask(TASK_FIREWALL_INSERT_RULES,
                         src_module=self.get_name(),
                         dest_module=SilentDuneClientFirewallModule().get_name(),
                         data=rules)
        self.send_parent_task(task)

    def get_http_rule_by_hostname(self):

        rules = list()

        port = self._uri.port
        if not port:
            port = 80

        ipaddrs = self.get_ip_from_hostname(self._uri.hostname, None)

        if not ipaddrs:
            _logger.error('{0}: no ip addresses found from lookup, this is unexpected.'.format(self.get_name()))
            return None

        for ipaddr in ipaddrs:
            _logger.debug(
                '{0}: adding rules for: hostname: {1}, ip addr: {2}, port: {3}'.format(
                    self.get_name(), self._uri.hostname, ipaddr, port))
            rules.append(create_iptables_egress_ingress_rule(ipaddr, port, 'tcp', self._slot_config_access,
                                                             transport=ipt.TRANSPORT_AUTO))

        return rules

    def get_https_rule_by_hostname(self):

        rules = list()

        port = self._uri.port
        if not port:
            port = 443

        ipaddrs = self.get_ip_from_hostname(self._uri.hostname, None)

        if not ipaddrs:
            _logger.error('{0}: no ip addresses found from lookup, this is unexpected.'.format(self.get_name()))
            return None

        for ipaddr in ipaddrs:
            _logger.debug(
                '{0}: adding rules for: hostname: {1}, ip addr: {2}, port: {3}'.format(
                    self.get_name(), self._uri.hostname, ipaddr, port))
            rules.append(create_iptables_egress_ingress_rule(ipaddr, port, 'tcp', self._slot_config_access,
                                                             transport=ipt.TRANSPORT_AUTO))

        return rules

    def get_ftp_rule_by_hostname(self):

        rules = list()

        port = self._uri.port
        if not port:
            port = 21

        ipaddrs = self.get_ip_from_hostname(self._uri.hostname, None)

        if not ipaddrs:
            _logger.error('{0}: no ip addresses found from lookup, this is unexpected.'.format(self.get_name()))
            return None

        for ipaddr in ipaddrs:
            _logger.debug(
                '{0}: adding rules for: hostname: {1}, ip addr: {2}, ftp ports: {3}, 20, etc'.format(
                    self.get_name(), self._uri.hostname, ipaddr, port))
            # FTP control
            rules.append(create_iptables_egress_ingress_rule(ipaddr, port, u'tcp', self._slot_config_access,
                                                             transport=ipt.TRANSPORT_AUTO))
            # FTP data transfer
            rules.append(
                create_iptables_egress_rule_dest(ipaddr, 20, u'tcp', self._slot_config_access, u'ESTABLISHED',
                                                 transport=ipt.TRANSPORT_AUTO))
            rules.append(create_iptables_ingress_rule_source(ipaddr, 20, u'tcp', self._slot_config_access,
                                                             u'ESTABLISHED,RELATED', transport=ipt.TRANSPORT_AUTO))
            rules.append(create_iptables_egress_rule_dest(ipaddr, None, u'tcp', self._slot_config_access,
                                                          u'ESTABLISHED,RELATED', transport=ipt.TRANSPORT_AUTO))
            rules.append(
                create_iptables_ingress_rule_source(ipaddr, None, u'tcp', self._slot_config_access, u'ESTABLISHED',
                                                    transport=ipt.TRANSPORT_AUTO))

        return rules

    def get_ip_from_hostname(self, hostname, port):

        ipaddrs = list()

        if not hostname:
            _logger.debug('{0}: no hostname specified, unable to do lookup'.format(self.get_name()))
            return None

        if port and not (1 < port <= 65536):
            _logger.debug('{0}: port value out of range, unable to do lookup'.format(self.get_name()))
            return None

        try:
            ais = socket.getaddrinfo(hostname, port, 0, 0, socket.IPPROTO_TCP)

            for result in ais:
                ipaddr = result[-1][0]
                ipaddrs.append(ipaddr)

        except:
            _logger.error('{0} unable to resolve hostname ({0})'.format(self.get_name(), hostname))
            return None

        return ipaddrs

    def apply_remote_config(self):

        rules = list()

        try:

            if self._uri.scheme == 'file':
                with open(self._uri.path) as handle:
                    rq = handle.read().decode('utf-8')
            else:
                rq = requests.get(self._remote_config_url, verify=False)

                if rq.status_code != 200:
                    _logger.error('{0}: unable to retrieve remote configuration'.format(self.get_name()))
                    return False
        except:
            _logger.error('{0}: unable to retrieve remote config rules'.format(self.get_name()))
            return False

        try:
            if self._uri.scheme == 'file':
                rc = RemoteConfig(json.loads(rq))
                rule_text = rq
            else:
                rc = RemoteConfig(rq.json())
                rule_text = rq.text

        except:
            _logger.error('{0}: parsing configuration json failed'.format(self.get_name()))
            return False

        # See if we should check the hash value against a DNS TXT lookup hash value
        if self._remote_config_dns_name:

            if not rc.hash_method or rc.hash_method not in ['sha1', 'sha256', 'sha512']:
                _logger.error('{0}: unsupported hashing algorithm in remote config ({1})'.format(
                    self.get_name(), rc.hash_method))
                return False

            if rc.hash_method == 'sha1':
                hash_value = hashlib.sha1(rule_text).hexdigest()
            elif rc.hash_method == 'sha256':
                hash_value = hashlib.sha256(rule_text).hexdigest()
            elif rc.hash_method == 'sha512':
                hash_value = hashlib.sha512(rule_text).hexdigest()

            if self.get_remote_dns_hash() != hash_value:
                _logger.error('{0}: remote DNS TXT hash value does not match calculated hash'.format(self.get_name()))
                return False

        _logger.debug('{0}: deleting rules for slot {1}'.format(self.get_name(), self._slot_config_apply))
        task = QueueTask(TASK_FIREWALL_DELETE_SLOT,
                         src_module=self.get_name(),
                         dest_module=SilentDuneClientFirewallModule().get_name(),
                         data=self._slot_config_apply)
        self.send_parent_task(task)

        for rule in rc.rules:

            try:

                # See if we need to try and resolve the host name
                if not is_valid_ipv6_address(rule.host) and not is_valid_ipv6_address(rule.host):

                    addrs = self.get_ip_from_hostname(rule.host, rule.port)

                    if not addrs:
                        _logger.error('{0}: error: unable to resolve rule host {1}'.format(self.get_name(), rule.host))
                        return False

                    for addr in addrs:
                        _logger.debug('{0}: adding rules slot: {1}, ip address: {2}, port: {3}, protocol: {4}'.format(
                            self.get_name(), self._slot_config_apply, addr, rule.port, rule.protocol))
                        rules.append(create_iptables_remote_config(addr, rule.mask, rule.port, rule.protocol,
                                                                   self._slot_config_apply, rule.uid, rule.gid,
                                                                   transport=ipt.TRANSPORT_AUTO))

                else:
                    _logger.debug('{0}: adding rules slot: {1}, ip address: {2}, port: {3}, protocol: {4}'.format(
                        self.get_name(), self._slot_config_apply, rule.host, rule.port, rule.protocol))
                    rules.append(create_iptables_remote_config(rule.host, rule.mask, rule.port, rule.protocol,
                                                               self._slot_config_apply, rule.uid, rule.gid,
                                                               transport=ipt.TRANSPORT_AUTO))

            except:
                _logger.error('{0}: parsing remote config rule failed.'.format(self.get_name()))
                return False

        if rules:
            task = QueueTask(TASK_FIREWALL_INSERT_RULES,
                             src_module=self.get_name(),
                             dest_module=SilentDuneClientFirewallModule().get_name(),
                             data=rules)
            self.send_parent_task(task)

        return True

    def get_remote_dns_hash(self):
        """
        Retrieve the remote config hash value stored in the given DNS TXT field name
        :return:
        """
        query = self._remote_config_dns_name

        if not query:
            return None

        try:
            answers = dns.resolver.query(query, 'TXT')

            for rdata in answers:
                for txt_string in rdata.strings:
                    return txt_string

        except:
            _logger.error('{0}: remote config DNS hash retrieval failed ({1})'.format(self.get_name(), query))

        return None
