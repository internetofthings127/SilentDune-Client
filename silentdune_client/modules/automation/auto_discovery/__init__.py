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

import ast
import hashlib
import logging
import socket
import sys
import time

from silentdune_client.utils.module_loading import import_by_str
from silentdune_client.utils.misc import is_service_running
from silentdune_client.modules import BaseModule, QueueTask
from silentdune_client.modules.firewall.manager.slots import Slots
from silentdune_client.modules.firewall.manager import SilentDuneClientFirewallModule, \
    TASK_FIREWALL_INSERT_RULES, TASK_FIREWALL_DELETE_SLOT, TASK_FIREWALL_ALLOW_ALL_DNS_ACCESS, \
    TASK_FIREWALL_DISABLE_ALL_DNS_ACCESS, TASK_FIREWALL_DISABLE_ALL_NTP_ACCESS, TASK_FIREWALL_ALLOW_ALL_NTP_ACCESS
from silentdune_client.builders import iptables as ipt
from silentdune_client.modules.firewall.manager.iptables_utils import resolve_hostname

_logger = logging.getLogger('sd-client')

TASK_RELOAD_AUTO_RULES = 100

module_list = {
    'Silent Dune Auto Service Discovery': {
        'module': 'SilentDuneAutoServiceDiscoveryModule',
    },
}

AUTO_DISCOVERY_SERVICE_LIST = (
    "silentdune_client.modules.automation.auto_discovery.dns.DynamicNameServiceDiscovery",  # Slot 130
    "silentdune_client.modules.automation.auto_discovery.ntp.NetworkTimeProtocolDiscovery",  # Slot 140
    "silentdune_client.modules.automation.auto_discovery.dhcp.DynamicHostConfigurationProtocolDiscovery",  # Slot 170
    "silentdune_client.modules.automation.auto_discovery.icmp.IcmpDiscovery",  # Slot 180
    "silentdune_client.modules.automation.auto_discovery.updates.SystemUpdatesDiscovery",  # Slot 150
    # Identity services (LDAP, FreeIPA, ...)  # Slot 160
)

NTP_DISCOVERY_SERVICE = "silentdune_client.modules.automation.auto_discovery.ntp.NetworkTimeProtocolDiscovery"


class SilentDuneAutoServiceDiscoveryModule(BaseModule):
    """
    Auto discover required external services by this system. IE: DNS, NTP, Updates, DHCP, ...
    """
    # Module properties
    _disable_auto_dns = False
    _disable_auto_ntp = False
    _disable_auto_updates = False
    _disable_auto_updates_ftp = False
    _disable_auto_dhcp = False
    _disable_auto_icmp = False

    # Timed events
    _t_all_service_check = 0  # Counter for next all service check
    _t_all_check_interval = 3600  # One hour

    _t_ntp_service_check = 0  # Counter for next NTP service check
    _t_ntp_check_interval = 300  # Five minutes

    _startup = True
    _all_dns_access_enabled = False
    _all_ntp_access_enabled = False

    _flat_rules = None  # Used in the flatten_rules() method

    priority = 10  # High priority startup.

    def __init__(self):

        self._arg_name = 'autodiscover'  # Set argparser name
        self._config_section_name = 'auto_discovery'  # Set configuration file section name

        # Enable multi-threading
        self.wants_processing_thread = True

        self._enabled = False

    def add_installer_arguments(self, parser):
        """
        Virtual Override
        Add our module's argparser arguments
        """

        # Create a argument group for our module
        group = parser.add_argument_group('auto discovery module', 'Silent Dune Auto Discovery module')

        group.add_argument('--discovery-mod-enable', action='store_true',  # noqa
                           help=_('Enable the auto discovery module'))  # noqa

        group.add_argument(_('--disable-auto-dns'), help=_('Disable auto DNS discovery.'),  # noqa
                           default=False, action='store_true')  # noqa
        group.add_argument(_('--disable-auto-ntp'), help=_('Disable auto NTP discovery.'),  # noqa
                           default=False, action='store_true')  # noqa
        group.add_argument(_('--disable-auto-updates'), help=_('Disable auto System Updates discovery.'),  # noqa
                           default=False, action='store_true')  # noqa
        group.add_argument(_('--disable-auto-updates-ftp'), help=_('Disable FTP rule creation for System Updates.'),  # noqa
                           default=False, action='store_true')  # noqa
        group.add_argument(_('--disable-auto-dhcp'), help=_('Disable auto DHCP discovery.'),  # noqa
                           default=False, action='store_true')  # noqa
        group.add_argument(_('--disable-auto-icmp'), help=_('Disable auto ICMP discovery.'),  # noqa
                           default=False, action='store_true')  # noqa

    def validate_arguments(self, args):
        """
        Virtual Override
        Validate command line arguments and save values to our configuration object.
        :param args: An argparse object.
        """
        # See if we have been enabled or not
        if '--discovery-mod-enable' not in sys.argv:
            return True

        if '--disable-auto-updates' in sys.argv and (
                '--disable-auto-updates-ftp' in sys.argv):
            print('sdc-install: argument --disable-auto-updates conflicts with other auto discover module arguments.')
            return False

        if args.discovery_mod_enable:
            self._enabled = args.discovery_mod_enable

        # Check for any required arguments here

        self._disable_auto_dns = args.disable_auto_dns
        self._disable_auto_ntp = args.disable_auto_ntp
        self._disable_auto_updates = args.disable_auto_updates
        self._disable_auto_updates_ftp = args.disable_auto_updates_ftp
        self._disable_auto_dhcp = args.disable_auto_dhcp
        self._disable_auto_icmp = args.disable_auto_icmp

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

            self._disable_auto_dns = \
                True if config.get(self._config_section_name, 'disable_auto_dns').lower() == 'yes' else False
            self._disable_auto_ntp = \
                True if config.get(self._config_section_name, 'disable_auto_ntp').lower() == 'yes' else False
            self._disable_auto_updates = \
                True if config.get(self._config_section_name, 'disable_auto_updates').lower() == 'yes' else False
            self._disable_auto_updates_ftp = \
                True if config.get(self._config_section_name, 'disable_auto_updates_ftp').lower() == 'yes' else False
            self._disable_auto_dhcp = \
                True if config.get(self._config_section_name, 'disable_auto_dhcp').lower() == 'yes' else False
            self._disable_auto_icmp = \
                True if config.get(self._config_section_name, 'disable_auto_icmp').lower() == 'yes' else False

        return True

    def prepare_config(self, config):
        """
        Virtual Override
        Return the configuration file structure. Any new configuration items should be added here.
        Note: The order should be reverse of the expected order in the configuration file.
        """

        config.set(self._config_section_name, 'enabled', 'yes' if self._enabled else 'no')
        config.set(self._config_section_name, 'disable_auto_dns', 'yes' if self._disable_auto_dns else 'no')
        config.set(self._config_section_name, 'disable_auto_ntp', 'yes' if self._disable_auto_ntp else 'no')
        config.set(self._config_section_name, 'disable_auto_updates', 'yes' if self._disable_auto_updates else 'no')
        config.set(self._config_section_name, 'disable_auto_updates_ftp',
                   'yes' if self._disable_auto_updates_ftp else 'no')
        config.set(self._config_section_name, 'disable_auto_dhcp', 'yes' if self._disable_auto_dhcp else 'no')
        config.set(self._config_section_name, 'disable_auto_icmp', 'yes' if self._disable_auto_icmp else 'no')

        config.set_comment(self._config_section_name, self._config_section_name,
                           _('; Silent Dune Auto Discovery Module Configuration\n'))  # noqa
        config.set_comment(self._config_section_name, 'disable_auto_dns',
                           _('; Disable the auto DNS rule generation.\n'))  # noqa
        config.set_comment(self._config_section_name, 'disable_auto_ntp',
                           _('; Disable the auto NTP rule generation.\n'))  # noqa
        config.set_comment(self._config_section_name, 'disable_auto_updates',
                           _('; Disable the auto System Update rule generation.\n'))  # noqa
        config.set_comment(self._config_section_name, 'disable_auto_updates_ftp',
                           _('; Disable the auto System Update FTP rule generation.\n'))  # noqa
        config.set_comment(self._config_section_name, 'disable_auto_dhcp',
                           _('; Disable the auto DHCP rule generation.\n'))  # noqa
        config.set_comment(self._config_section_name, 'disable_auto_icmp',
                           _('; Disable the auto ICMP rule generation.\n'))  # noqa

        return True

    def service_startup(self):
        _logger.debug('{0}: module startup called'.format(self.get_name()))

        if not self.validate_config(self.config):
            _logger.error('{0}: module configuration validation failed.'.format(self.get_name()))
            return False

        if not self._enabled:
            return True

        return True

    def service_shutdown(self):
        _logger.debug('{0}: module shutdown called'.format(self.get_name()))

    def process_loop(self):

        if self._startup:

            # Try resolving example.org, if we get an error try enabling generic all DNS access.
            # This block may be called multiple times during startup to make sure DNS is working.
            try:
                resolve_hostname('example.org', ipt.TRANSPORT_AUTO)
            except socket.gaierror:

                # If we have reached here, we have no DNS access at all.
                if self._all_dns_access_enabled:
                    # raise OSError('No external DNS access available. Unable to complete auto discovery.')
                    _logger.error('{0}: No external DNS available. Waiting 5 minutes to try again.'.format(
                        self.get_name()))
                    time.sleep(300)
                    return

                _logger.debug('{0}: Asking Firewall Module to enable generic DNS access.'.format(self.get_name()))

                # Tell the firewall manager to enable generic all DNS access.
                self._all_dns_access_enabled = True

                task = QueueTask(TASK_FIREWALL_ALLOW_ALL_DNS_ACCESS,
                                 src_module=self.get_name(),
                                 dest_module=SilentDuneClientFirewallModule().get_name())
                self.send_parent_task(task)

                return

            self._startup = False
            self.discover_services()

            # Tell the firewall manager to remove generic all DNS access rules.
            if self._all_dns_access_enabled:
                self._all_dns_access_enabled = False
                _logger.debug('{0}: Asking Firewall Module to disable generic DNS access.'.format(self.get_name()))
                task = QueueTask(TASK_FIREWALL_DISABLE_ALL_DNS_ACCESS,
                                 src_module=self.get_name(),
                                 dest_module=SilentDuneClientFirewallModule().get_name())
                self.send_parent_task(task)

        # After the check interval has passed, check services again.
        if self.timed_event('_t_all_service_check', self._t_all_check_interval):
            self.discover_services()

        # See we need to remove the all access ntp rules.
        if self._all_ntp_access_enabled and self.timed_event('_t_ntp_service_check', self._t_ntp_check_interval):

            rule_count = self.check_service(NTP_DISCOVERY_SERVICE)

            # If we found NTP rules, tell the firewall manager to remove generic all NTP access rules.
            if self._all_ntp_access_enabled and rule_count > 0:

                self._all_ntp_access_enabled = False
                _logger.debug('{0}: Asking Firewall Module to disable generic NTP access.'.format(self.get_name()))
                task = QueueTask(TASK_FIREWALL_DISABLE_ALL_NTP_ACCESS,
                                 src_module=self.get_name(),
                                 dest_module=SilentDuneClientFirewallModule().get_name())
                self.send_parent_task(task)

    def process_task(self, task):
        """
        Process any tasks we receive from other modules
        :param task: Task Object
        """

        if task:
            t_id = task.get_task_id()

            # We've been told we need to reload the auto rules.
            if t_id == TASK_RELOAD_AUTO_RULES:
                self.discover_services()

    def discover_services(self):
        """
        Loop through the auto discovery class list and call discover() for each class found.
        If any firewall rules are found, send them to the firewall manager service.

        Note: Each slot id used in each discovery class needs to be unique.
        """
        for name in AUTO_DISCOVERY_SERVICE_LIST:
            self.check_service(name)

    def check_service(self, name):
        """
        Check the service for rules and add them to the firewall.
        :param name: Service discovery module name
        """
        module_name, class_name = name.rsplit('.', 1)

        _logger.debug('{0}: Loading auto discover object {1}'.format(self.get_name(), class_name))

        module = import_by_str(name)
        cls = module(config=self.config)
        disabled = getattr(self, cls.get_config_property_name())
        if type(disabled) is str:  # Python 2.7 returns string type from getattr(), Python 3.4 returns bool.
            disabled = ast.literal_eval(disabled)

        # _logger.debug('Property: {0}: Value: {1}'.format(cls.get_config_property_name(), disabled))
        # See if this discovery service has been disabled. Name value must match one of our property names.
        if disabled:
            _logger.debug('{0}: {1} discovery service disabled by config.'.format(self.get_name(), class_name))
            return 0

        rules, slot = cls.discover(self)

        rules = self.flatten_rules(rules)

        if rules:

            # Notify the firewall module to delete the old rules.
            task = QueueTask(TASK_FIREWALL_DELETE_SLOT,
                             src_module=self.get_name(),
                             dest_module=SilentDuneClientFirewallModule().get_name(),
                             data=slot)
            self.send_parent_task(task)

            # Notify the firewall module to load the new rules.
            task = QueueTask(TASK_FIREWALL_INSERT_RULES,
                             src_module=self.get_name(),
                             dest_module=SilentDuneClientFirewallModule().get_name(),
                             data=rules)
            self.send_parent_task(task)

            time.sleep(1)  # Let the firewall apply the rule changes
        else:
            _logger.info('{0}: {1}: discovery service did not return any rules.'.format(
                self.get_name(), class_name))

            _logger.debug('SLOTS: {0}: {1}'.format(Slots.ntp, slot))

            # If there were no rules discovered for NTP, open up access to all NTP servers.
            # In self._t_ntp_check_interval seconds we will check to see if any NTP servers are active.
            if slot == Slots.ntp and is_service_running('ntpd'):
                self._all_ntp_access_enabled = True
                _logger.debug('{0}: Asking Firewall Module to enable generic NTP access.'.format(self.get_name()))
                task = QueueTask(TASK_FIREWALL_ALLOW_ALL_NTP_ACCESS,
                                 src_module=self.get_name(),
                                 dest_module=SilentDuneClientFirewallModule().get_name())
                self.send_parent_task(task)

            return 0

        return len(rules)

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
