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

from silentdune_client.modules.firewall.manager.slots import Slots
from silentdune_client.modules.automation.auto_discovery.base_discovery_service import BaseDiscoveryService
from silentdune_client.modules.firewall.manager.iptables_utils import create_iptables_tcp_egress_ingress_rule, create_iptables_udp_egress_ingress_rule

_logger = logging.getLogger('sd-client')


class DynamicNameServiceDiscovery(BaseDiscoveryService):
    """
    Auto discover DNS servers from local system configuration files.
    """

    _slot = Slots.dns  # DNS slot value = 130
    _config_property_name = '_disable_auto_dns'

    def _discover_iptables(self):
        """
        Look at /etc/resolv.conf file to get external DNS servers and set outbound rule(s) to allow access.
        """

        if not os.path.exists('/etc/resolv.conf'):
            _logger.error('{0}: resolv.conf not found.'.format(self.get_name()))
            return None

        rules = list()
        ipaddrs = list()

        # Get all nameserver ip address values
        with open('/etc/resolv.conf') as handle:
            for line in handle:
                if 'nameserver' in line.lower() and not line.strip().startswith('#'):
                    ipaddrs.append(line.split()[1])

        if len(ipaddrs) == 0:
            _logger.error('{0}: no name server values found in resolv.conf'.format(self.get_name()))
            return None

        for ipaddr in ipaddrs:
            try:
                _logger.debug('{0}: adding DNS IP address {1}'.format(self.get_name(), ipaddr))
                rules.append(create_iptables_tcp_egress_ingress_rule(ipaddr, 53, self._slot))
                rules.append(create_iptables_udp_egress_ingress_rule(ipaddr, 53, self._slot))
            except ValueError:
                _logger.error('{0}: Unable to validate DNS ip address {1}.'.format(self.get_name(), ipaddr))

        return rules
