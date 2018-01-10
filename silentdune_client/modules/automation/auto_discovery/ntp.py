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
import subprocess
import shlex

from silentdune_client.modules.firewall.manager.slots import Slots
from silentdune_client.builders import iptables as ipt
from silentdune_client.modules.automation.auto_discovery.base_discovery_service import BaseDiscoveryService
from silentdune_client.modules.firewall.manager.iptables_utils import create_iptables_udp_egress_ingress_rule
from silentdune_client.utils.misc import which, is_service_running

_logger = logging.getLogger('sd-client')


class NetworkTimeProtocolDiscovery(BaseDiscoveryService):
    """
    Auto discover NTP.
    """

    _slot = Slots.ntp
    _config_property_name = '_disable_auto_ntp'

    def _discover_iptables(self):

        rules = list()

        ntpq = which(u'ntpq')
        if not ntpq:
            _logger.debug('Failed to find program path for "{0}"'.format('ntpq'))
            return rules

        # Check to see if ntpd is running
        if not is_service_running('ntpd'):
            _logger.debug('ntpd is not running.')
            return rules

        p = subprocess.Popen(shlex.split('ntpq -p -n'), stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        result = p.wait()
        
        if stderrdata is None:
            data = stdoutdata.decode('utf-8')
            for line in data.split('\n'):
                item = line.split(' ', 1)
                if item[0][:1] == '+' or item[0][:1] == '-' or item[0][:1] == '*' or item[0][:1] == 'x' or \
                                item[0][:1] == '.' or item[0][:1] == '#' or item[0][:1] == 'o':
                    ipaddr = item[0][1:]

                    _logger.debug('{0}: adding NTP Client Rules for {1}'.format(self.get_name(), ipaddr))
                    rules.append(create_iptables_udp_egress_ingress_rule(
                        ipaddr, 123, self._slot, transport=ipt.TRANSPORT_AUTO))

        return rules
