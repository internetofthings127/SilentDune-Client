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
import sys

from silentdune_client.modules import BaseModule, QueueTask

from silentdune_client.utils.module_loading import import_by_str
from silentdune_client.modules.firewall.manager import SilentDuneClientFirewallModule, \
    TASK_FIREWALL_INSERT_RULES, TASK_FIREWALL_DELETE_RULES

_logger = logging.getLogger('sd-client')

module_list = {
    'Silent Dune Auto Services': {
        'module': 'SilentDuneAutoServicesModule',
    },
}

AUTO_SERVICES_LIST = (
    "silentdune_client.modules.automation.auto_services.docker.DockerService",
)


class SilentDuneAutoServicesModule(BaseModule):

    _startup = True

    _enabled = False

    _mss_slots = {}  # Storage for machine_subset hashes and slot ids.  For detection of rule changes.

    def __init__(self):

        self._arg_name = 'autoservices'  # Set argparser name
        self._config_section_name = 'auto_services'  # Set configuration file section name

        # Enable multi-threading
        self.wants_processing_thread = True

    def add_installer_arguments(self, parser):
        """
        Virtual Override
        Add our module's argparser arguments
        """

        # Create a argument group for our module
        group = parser.add_argument_group('auto services module', 'Silent Dune Auto Services module')

        group.add_argument('--services-mod-enable', action='store_true',  # noqa
                           help=_('Enable the auto services module'))  # noqa

        # TODO: Add in --services-disable-service as a multi value argparse argument

    def validate_arguments(self, args):
        """
        Virtual Override
        Validate command line arguments and save values to our configuration object.
        :param args: An argparse object.
        """
        # See if we have been enabled or not
        if '--services-mod-enable' not in sys.argv:
            return True

        if args.services_mod_enable:
            self._enabled = True

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

    def prepare_config(self, config):
        """
        Virtual Override
        Return the configuration file structure. Any new configuration items should be added here.
        Note: The order should be reverse of the expected order in the configuration file.
        """

        config.set(self._config_section_name, 'enabled', 'yes' if self._enabled else 'no')

        config.set_comment(self._config_section_name, self._config_section_name,
                           _('; Silent Dune Auto Services Module Configuration\n'))  # noqa

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
            self.find_active_services()

    def find_active_services(self):
        """
        Loop through the services list and call discover() for each class found.
        """
        for name in AUTO_SERVICES_LIST:
            rule_count = self.check_service(name)

    def check_service(self, name):
        """
        Check the service for rules and add them to the firewall.
        :param name: Service discovery module name
        """
        module_name, class_name = name.rsplit('.', 1)

        _logger.debug('{0}: Loading service object {1}'.format(self.get_name(), class_name))

        module = import_by_str(name)
        cls = module(config=self.config)
        disabled = getattr(self, cls.get_config_property_name())
        if type(disabled) is str:  # Python 2.7 returns string type from getattr(), Python 3.4 returns bool.
            disabled = ast.literal_eval(disabled)

        # _logger.debug('Property: {0}: Value: {1}'.format(cls.get_config_property_name(), disabled))
        # See if this discovery service has been disabled. Name value must match one of our property names.
        if disabled:
            _logger.debug('{0}: {1} service disabled by config.'.format(self.get_name(), class_name))
            return 0

        rules, slot = cls.discover()

        if rules:

            # See if we already have saved rules for this slot id
            if slot in self._mss_slots:
                if self.rules_have_changed(self._mss_slots[slot], rules):

                    _logger.debug('{0}: {1}: Rules have changed, notifying firewall manager.'.format(
                        self.get_name(), class_name))

                    # Notify the firewall module to delete the old rules.
                    task = QueueTask(TASK_FIREWALL_DELETE_RULES,
                                     src_module=self.get_name(),
                                     dest_module=SilentDuneClientFirewallModule().get_name(),
                                     data=self._mss_slots[slot])
                    self.send_parent_task(task)
                else:
                    return 0

            # Save rules so we can check against them next time.
            self._mss_slots[slot] = rules

            # Notify the firewall module to reload the rules.
            task = QueueTask(TASK_FIREWALL_INSERT_RULES,
                             src_module=self.get_name(),
                             dest_module=SilentDuneClientFirewallModule().get_name(),
                             data=rules)
            self.send_parent_task(task)
        else:
            _logger.info('{0}: {1}: service did not return any rules.'.format(
                self.get_name(), class_name))

            return 0

        return len(rules)

    def rules_have_changed(self, old, new):
        """
        Compare rules and see if they are different.
        :param old: List of machine_subset objects
        :param new: List of machine_subset objects
        :return: True if old and new rules are different
        """

        old_rules = ''
        new_rules = ''

        for mss in old:
            old_rules += mss.to_json()

        for mss in new:
            new_rules += mss.to_json()

        return hashlib.sha1(old_rules).hexdigest() != hashlib.sha1(new_rules).hexdigest()

