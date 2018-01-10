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

from silentdune_client.modules import BaseModule, QueueTask
from silentdune_client.modules.firewall.manager import SilentDuneClientFirewallModule, TASK_FIREWALL_RELOAD_RULES

_logger = logging.getLogger('sd-client')

module_list = {
    'Silent Dune Simple Example': {
        'module': 'SilentDuneSimpleModuleExample',
    },
}


class SilentDuneSimpleModuleExample(BaseModule):

    _t_debug_message = 0  # Timed event property for debug message loop.
    _t_reload_task = 0  # Timed event property for reloading firewall rules.

    _enabled = False

    def __init__(self):

        self._arg_name = 'simple'  # Set argparser name
        self._config_section_name = 'simple_module'  # Set configuration file section name

        # Enable multi-threading
        self.wants_processing_thread = True

    def process_loop(self):

        # Print a debug message every 45 seconds
        if self.timed_event('_t_debug_message', 45):
            _logger.debug('{0} 45 second debug message'.format(self.get_name()))

        # Tell the firewall module to reload the firewall rules every 2 minutes.
        if self.timed_event('_t_reload_task', 120):
            # Notify the firewall module to reload the rules.
            task = QueueTask(TASK_FIREWALL_RELOAD_RULES,
                             src_module=self.get_name(),
                             dest_module=SilentDuneClientFirewallModule().get_name())
            self.send_parent_task(task)
