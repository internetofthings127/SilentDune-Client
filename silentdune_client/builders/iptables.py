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

from silentdune_client.models.iptables_rules import IPJumpOptions, IPJump, IPMatchOptions, \
    IPMatch, IPRule, IPRing, IPChain, IPMachineSubset

TRANSPORT_IPV4 = u'ipv4'
TRANSPORT_IPV6 = u'ipv6'
TRANSPORT_AUTO = u'auto'


def get_machine_subset(name, slot, chains, platform=u'iptables', _id=0):
    """
    Return an IPMachineSubset object
    :param name: Name for this group of rules
    :param slot: Slot ID for this group
    :param chains: List of IPChains objects
    :param platform: Must be 'iptables'
    :param _id: Id for this object
    :return:
    """
    obj = IPMachineSubset({u'name': name, u'slot': slot, u'platform': platform, u'id': _id})
    obj.chains = chains
    return obj


def get_chain(name, rings, _id=0):
    """

    :param name: iptables table name, must be 'filter', 'nat', 'mangle', 'raw' or 'security'
    :param rings: List of IPRing objects
    :param _id: Id for this object
    :return:
    """
    obj = IPChain({u'name': name, u'id': _id})
    obj.rings = rings
    return obj


def get_ring(name, version, rules, _id=0):
    """

    :param name: iptables chain name, must be 'INPUT', 'OUTPUT', 'PREROUTING', 'POSTROUTING', or 'FORWARD'
    :param version: Transport version, must be 'ipv4' or 'ipv6'
    :param rules: List of IPRule objects
    :param _id: Id for this object
    :return:
    """
    obj = IPRing({u'name': name, u'version': version, u'id': _id})
    obj.rules = rules
    return obj


def get_rule(desc=None, ifacein_name=None, ifacein_invert=None, ifaceout_name=None,
             ifaceout_invert=None, ip_protocol_name=None, ip_protocol_invert=None, source_address=None,
             source_mask=None, source_invert=None, dest_address=None, dest_mask=None, dest_invert=None,
             fragment=None, fragment_invert=None, enabled=True, sortId=0, matches=None, jump=None, _id=0):
    """
    Return an IPRule object
    :param matches: List of IPMatch objects
    :param jump: Single IPJump object
    :return:
    """
    obj = IPRule({u'desc': desc,
                  u'ifacein_name': ifacein_name,
                  u'ifacein_invert': ifacein_invert,
                  u'ifaceout_name': ifaceout_name,
                  u'ifaceout_invert': ifaceout_invert,
                  u'ip_protocol_name': ip_protocol_name,
                  u'ip_protocol_invert': ip_protocol_invert,
                  u'source_address': source_address,
                  u'source_mask': source_mask,
                  u'source_invert': source_invert,
                  u'dest_address': dest_address,
                  u'dest_mask': dest_mask,
                  u'dest_invert': dest_invert,
                  u'fragment': fragment,
                  u'fragment_invert': fragment_invert,
                  u'enabled': enabled,
                  u'sortId': sortId,
                  u'id': _id})
    obj.matches = matches
    obj.jump = jump
    return obj


def get_match(name, options, _id=0):
    """

    :param name: Match name
    :param options: List of IPMatchOptions objects
    :param _id: Id for this object
    :return: IPMatch object
    """
    obj = IPMatch({u'name': name, u'id': _id})
    obj.options = options
    return obj


def get_match_option(option, value, invert=False, sort_id=0, _id=0):
    """

    :param option: Option name
    :param value: Option value
    :param invert: Invert option meaning
    :param sort_id: sorting value for this object
    :param _id: Id for this object
    :return: IPMatchOptions object
    """
    return IPMatchOptions({u'option': option, u'value': value, u'invert': invert, u'sortId': sort_id, u'id': _id})


def get_jump(target='ACCEPT', params=None, _id=0):
    """
    Return an IPJump object
    :param target: Jump target value.
    :param params: IPJumpOptions object
    :param _id: Id for this object
    :return: IPJump object
    """
    obj = IPJump({u'id': _id, u'target': target})
    obj.params = params
    return obj


def get_jump_option(name, value=None, _id=0):
    """
    Return a IPJumpOptions object
    :param name: Jump option name
    :param value: Jump option value
    :param _id: Id for this object
    :return: IPJumpOptions object
    """
    return IPJumpOptions({u'name': name, u'value': value, u'id': _id})
