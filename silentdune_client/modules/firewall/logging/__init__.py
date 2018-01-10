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


import logging
import os
import re
import sys
import pkg_resources

from silentdune_client.models.iptables_log_event import IPLogEvent
from silentdune_client.builders import iptables as ipt
from silentdune_client.modules import BaseModule, QueueTask
from silentdune_client.modules.firewall.manager import SilentDuneClientFirewallModule, \
    TASK_FIREWALL_INSERT_RULES

_logger = logging.getLogger('sd-client')

""" Let other modules subscribe to logging events """
TASK_SUBSCRIBE_LOG_EVENTS = 100
TASK_UNSUBSCRIBE_LOG_EVENTS = 110
TASK_LOG_EVENT = 9800  # Line up with the slot id of log records.

# Define the available Module classes.
module_list = {
    'Silent Dune Firewall Manager': {
        'module': 'SilentDuneClientLoggingModule',
    },
}


class SilentDuneClientLoggingModule(BaseModule):
    """ Silent Dune Logging Module """

    priority = 10  # Second highest loading priority.

    _log_file_list = ['/var/log/firewall', '/var/log/messages', '/var/log/kern.log']
    _log_file = None
    _log_handle = None  # Log file handle.
    _log_offset = 0  # Current offset in file.
    _terminators = ('\r\n', '\n', '\r')

    _subscribers = list()

    # Module properties
    _limit_rate = None
    _limit_rate_regex = "^(\d*?)/(second|minute|hour|day|sec|min)$"

    _startup = True

    def __init__(self):

        self._arg_name = 'logging'
        self._config_section_name = 'logging_module'

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
        group = parser.add_argument_group('logging module', 'Silent Dune Logging module')

        group.add_argument('--logging-mod-enable', action='store_true',  # noqa
                           help=_('Enable the logging module'))  # noqa

        group.add_argument('--logging-limit-rate', default='10/min', type=str,  # noqa
                           help=_('Limit log events. (rate[/second|/minute|/hour|/day])'))  # noqa

    def validate_arguments(self, args):
        """
        Virtual Override
        Validate command line arguments and save values to our configuration object.
        :param args: An argparse object.
        """
        # See if we have been enabled or not
        if '--logging-mod-enable' not in sys.argv:
            return True

        if args.logging_mod_enable:
            self._enabled = True
            return True

        # Check for any required arguments here

        # Check logging match rate argument against regex.
        if not re.match(self._limit_rate_regex, args.logging_limit_rate):
            print('sdc-install: argument --logging-limit-rate value is invalid.')
            return False

        self._limit_rate = args.logging_limit_rate

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

            self._limit_rate = config.get(self._config_section_name, 'logging_limit_rate')
            if not re.match(self._limit_rate_regex, self._limit_rate):
                _logger.warn('{0} limit rate value is invalid, defaulting to "6/min".')
                self._limit_rate = '6/min'

        return True

    def prepare_config(self, config):
        """
        Virtual Override
        Return the configuration file structure. Any new configuration items should be added here.
        Note: The order should be reverse of the expected order in the configuration file.
        """

        config.set(self._config_section_name, 'enabled', 'yes' if self._enabled else 'no')
        config.set(self._config_section_name, 'logging_limit_rate', self._limit_rate)

        config.set_comment(self._config_section_name, self._config_section_name,
                           _('; Silent Dune Logging Module Configuration\n'))  # noqa
        config.set_comment(self._config_section_name, 'logging_limit_rate',
                           _('; Limit log events. (rate[/second|/minute|/hour|/day])\n'))  # noqa

        return True

    def service_startup(self):
        _logger.debug('{0} module startup called'.format(self.get_name()))

        # Check to see if we can open the log file or not.
        result = self.open_log()
        self.close_log()

        return result

    def open_log(self):

        for name in self._log_file_list:
            if os.path.exists(name):
                self._log_file = name

        if not self._log_file:
            return False

        try:
            self._log_handle = open(self._log_file)
            self._log_handle.seek(0, 2)  # Seek end of file
            self._log_offset = self._log_handle.tell()
        except IOError:
            _logger.error('{0}: Unable to open "{1}" for reading.'.format(self.get_name(), self._log_file))
            return False

        return True

    def close_log(self):

        if self._log_handle:
            self._log_handle.close()
            self._log_handle = None

    def service_shutdown(self):
        _logger.debug('{0} thread shutdown called'.format(self.get_name()))
        self.close_log()

    def process_loop(self):
        # _logger.debug('{0} processing loop called'.format(self.get_name()))

        if self._startup:
            self._startup = False

            task = QueueTask(TASK_FIREWALL_INSERT_RULES,
                             src_module=self.get_name(),
                             dest_module=SilentDuneClientFirewallModule().get_name(),
                             data=self.create_logging_rules())
            self.send_parent_task(task)

        if self._log_handle:

            # See if we have iptables log event data
            data = self._log_handle.readline()

            while data:

                if self.node_info.platform == 'linux' and 'kernel: SDC' in data:

                    # See tests/iptables_logging_test.py for example log events.
                    ev = IPLogEvent(data)

                    for mod_name in self._subscribers:
                        # _logger.debug('{0}: sending {1} log event.'.format(self.get_name(), mod_name))
                        task = QueueTask(TASK_LOG_EVENT,
                                         src_module=self.get_name(),
                                         dest_module=mod_name,
                                         data=ev)
                        self.send_parent_task(task)

                data = self._log_handle.readline()

    def process_task(self, task):

        if task:
            t_id = task.get_task_id()

            # Add a subscriber module to our subscribers list.
            if t_id == TASK_SUBSCRIBE_LOG_EVENTS:
                _logger.debug('{0}: {1}: {2}: subscribed.'.format(
                    self.get_name(), task.get_sender(), 'TASK_SUBSCRIBE_LOG_EVENTS'))

                name = task.get_sender()
                if name not in self._subscribers:
                    self._subscribers.append(name)

                    # If we haven't opened the log file, do so now.
                    if not self._log_handle:
                        self.open_log()

            # Remove a subscriber module from our list.
            if t_id == TASK_UNSUBSCRIBE_LOG_EVENTS:
                _logger.debug('{0}: {1}: {2}: unsubscribed.'.format(
                    self.get_name(), task.get_sender(), 'TASK_SUBSCRIBE_LOG_EVENTS'))

                name = task.get_sender()
                if name in self._subscribers:
                    self._subscribers.pop(name)

                    # Close log file if we have no subscribers.
                    if len(self._subscribers) == 0:
                        self.close_log()

    def create_logging_rules(self):

        rules = list()

        rules.append(ipt.get_machine_subset(
            u'ipv4 logging rule',
            9800,
            [
                ipt.get_chain(
                    u'filter',
                    [
                        ipt.get_ring(
                            u'output',
                            ipt.TRANSPORT_IPV4,
                            [
                                ipt.get_rule(
                                    matches=[
                                        ipt.get_match('limit', options=[
                                            ipt.get_match_option('--limit', self._limit_rate),
                                        ]),
                                    ],
                                    jump=ipt.get_jump(target=u'LOG', params=[
                                        ipt.get_jump_option(u'--log-level', value="alert"),
                                        ipt.get_jump_option(u'--log-prefix', value=u'SDC: '),
                                    ])
                                )
                            ]
                        ),
                    ]
                )
            ]
        )
        )

        rules.append(ipt.get_machine_subset(
            u'ipv4 logging rule',
            9800,
            [
                ipt.get_chain(
                    u'filter',
                    [
                        ipt.get_ring(
                            u'output',
                            ipt.TRANSPORT_IPV6,
                            [
                                ipt.get_rule(
                                    matches=[
                                        ipt.get_match('limit', options=[
                                            ipt.get_match_option('--limit', self._limit_rate),
                                        ]),
                                    ],
                                    jump=ipt.get_jump(target=u'LOG', params=[
                                        ipt.get_jump_option(u'--log-level', value="alert"),
                                        ipt.get_jump_option(u'--log-prefix', value=u'SDC: '),
                                    ])
                                )
                            ]
                        ),
                    ]
                )
            ]
        )
        )

        return rules
