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

"""
Generic utilities that apply to all firewall platforms.
"""

from silentdune_client.modules.firewall.manager.iptables_utils import create_iptables_generic_dns_egress_rules, \
    create_iptables_generic_ntp_egress_rules
from silentdune_client.utils.node_info import NodeInformation


def create_generic_dns_egress_rules():
    """
    Create generic DNS access rules.  Usually used temporarily to all DNS queries to succeed.
    :return: rules.
    """

    if NodeInformation.firewall_platform == 'iptables':
        return create_iptables_generic_dns_egress_rules()
    else:
        raise AttributeError


def create_generic_ntp_egress_rules():
    """
    Create generic NTP access rules.  Usually used temporarily to all NTP queries to succeed.
    :return: rules.
    """

    if NodeInformation.firewall_platform == 'iptables':
        return create_iptables_generic_ntp_egress_rules()
    else:
        raise AttributeError
