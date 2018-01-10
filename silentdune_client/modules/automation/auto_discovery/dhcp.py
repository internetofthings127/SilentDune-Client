#
# Authors: Ma He <mahe.itsec@gmail.com>
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

from silentdune_client.modules.firewall.manager.slots import Slots
from silentdune_client.builders import iptables as ipt
from silentdune_client.modules.automation.auto_discovery.base_discovery_service import BaseDiscoveryService
from silentdune_client.modules.firewall.manager.iptables_utils import create_iptables_udp_egress_ingress_rule

_logger = logging.getLogger('sd-client')


class DynamicHostConfigurationProtocolDiscovery(BaseDiscoveryService):
    """
    Auto discover DHCP.
    """

    _slot = Slots.dhcp
    _config_property_name = '_disable_auto_dhcp'

    def _discover_iptables(self):

        rules = list()

        _logger.debug('{0}: adding DHCP Client Rules.'.format(self.get_name()))
        rules.append(create_iptables_udp_egress_ingress_rule(None, 67, self._slot, transport=ipt.TRANSPORT_IPV4))
        rules.append(create_iptables_udp_egress_ingress_rule(None, 67, self._slot, transport=ipt.TRANSPORT_IPV6))

        return rules
