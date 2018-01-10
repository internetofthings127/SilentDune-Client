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

from silentdune_client.utils.node_info import NodeInformation


_logger = logging.getLogger('sd-client')


class BaseService(object):
    """
    Simple base object for auto service.
    """

    _slot = 0  # Set this to the proper slot level value.
    _service_name = 'unknown'  # Config property name in SilentDuneAutoServicesModule.
    _module = 'SilentDuneAutoServicesModule'

    def get_name(self):
        """
        :return: module name
        """
        # return self._name
        return type(self).__name__

    def get_slot(self):
        return self._slot

    def get_service_name(self):
        return self._service_name

    def discover(self):
        """
        Please DO NOT override this method. Override the platform specific discover methods.
        """
        if NodeInformation.firewall_platform == 'iptables':
            return self._discover_iptables(), self._slot

    def _discover_iptables(self):
        """
        Override this method to discover external services and return either a single machine_subset object or a
        list of machine_subset objects to add to the firewall rules.

        See: modules/firewall/manage/iptables_utils.py for iptables rule builder methods.

        :return: Single iptables machine_subset object or list of objects.
        """

        pass