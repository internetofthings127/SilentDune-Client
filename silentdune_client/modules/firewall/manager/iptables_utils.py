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
Generic Firewall function that apply to iptables platform.
"""

import socket

from silentdune_client.builders import iptables as ipt
from silentdune_client.modules.firewall.manager.slots import Slots
from silentdune_client.utils.misc import is_valid_ipv4_address, is_valid_ipv6_address


# Note: If this method is put in manager.utils it creates a circular reference.
def check_transport_value(ipaddr, transport):
    """
    Check the given transport version against the given IP address.
    :param ipaddr: IP address to check.
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :return: The correct ipt transport version.
    """

    if transport == ipt.TRANSPORT_AUTO:
        if is_valid_ipv6_address(ipaddr):
            transport = ipt.TRANSPORT_IPV6
        elif is_valid_ipv4_address(ipaddr):
            transport = ipt.TRANSPORT_IPV4
        else:
            raise ValueError('Invalid transport version ({0}:{1})'.format(ipaddr, str(transport)))
    elif transport == ipt.TRANSPORT_IPV4:
        if not is_valid_ipv4_address(ipaddr):
            raise ValueError('Invalid transport version ({0}:{1})'.format(ipaddr, str(transport)))
    elif transport == ipt.TRANSPORT_IPV6:
        if not is_valid_ipv6_address(ipaddr):
            raise ValueError('Invalid transport version ({0}:{1})'.format(ipaddr, str(transport)))
    else:
        raise ValueError('Invalid transport version ({0}:{1})'.format(ipaddr, str(transport)))

    return transport


def resolve_hostname(name, transport):
    """
    Resolve a hostname to an IP address.
    :param name: Hostname to resolve.
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :return: IP address. Using ipt.TRANSPORT_AUTO will always return an IPv4 IP address.
    """

    if not name:
        raise ValueError('Invalid host name parameter')

    if transport == ipt.TRANSPORT_IPV6:
        addr = socket.getaddrinfo(name, None, socket.AF_INET6, 0, socket.IPPROTO_TCP)[0][4][0]
    else:
        addr = socket.getaddrinfo(name, None, socket.AF_INET, 0, socket.IPPROTO_TCP)[0][4][0]

    return addr


def create_iptables_loopback(slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create an rule for loopback interface.
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    if transport == ipt.TRANSPORT_AUTO:
        raise ValueError('Unable to determine transport for loopback')

    return ipt.get_machine_subset(
        desc,
        slot,
        [
            ipt.get_chain(
                u'filter',
                [
                    ipt.get_ring(
                        u'input',
                        transport,
                        [
                            ipt.get_rule(ifacein_name=u'lo', jump=ipt.get_jump(target=u'ACCEPT'))
                        ]
                    ),
                    ipt.get_ring(
                        u'output',
                        transport,
                        [
                            ipt.get_rule(ifaceout_name=u'lo', jump=ipt.get_jump(target=u'ACCEPT'))
                        ]
                    ),
                ]
            )
        ]
    )


def create_iptables_icmp_all(slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create an rule for icmp traffic.
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    if transport == ipt.TRANSPORT_AUTO:
        raise ValueError('Unable to determine transport for icmp')
    elif transport == ipt.TRANSPORT_IPV4:
        protocol = u'icmp'
    elif transport == ipt.TRANSPORT_IPV6:
        protocol = u'icmpv6'

    return ipt.get_machine_subset(
        desc,
        slot,
        [
            ipt.get_chain(
                u'filter',
                [
                    ipt.get_ring(
                        u'input',
                        transport,
                        [
                            ipt.get_rule(
                                ip_protocol_name=protocol,
                                jump=ipt.get_jump(target=u'ACCEPT'))
                        ]
                    ),
                    ipt.get_ring(
                        u'output',
                        transport,
                        [
                            ipt.get_rule(
                                ip_protocol_name=protocol,
                                jump=ipt.get_jump(target=u'ACCEPT'))
                        ]
                    ),
                ]
            )
        ]
    )


def create_iptables_generic_dns_egress_rules():
    """
    Create generic egress rules to allow access to any DNS server.
    :return:
    """

    rules = list()

    rules.append(create_iptables_tcp_egress_ingress_rule(None, 53, Slots.dns, transport=ipt.TRANSPORT_IPV4,
                                                         desc=u'all DNS Rule'))
    rules.append(create_iptables_tcp_egress_ingress_rule(None, 53, Slots.dns, transport=ipt.TRANSPORT_IPV6,
                                                         desc=u'all DNS Rule'))
    rules.append(create_iptables_udp_egress_ingress_rule(None, 53, Slots.dns, transport=ipt.TRANSPORT_IPV4,
                                                         desc=u'all DNS Rule'))
    rules.append(create_iptables_udp_egress_ingress_rule(None, 53, Slots.dns, transport=ipt.TRANSPORT_IPV6,
                                                         desc=u'all DNS Rule'))

    return rules


def create_iptables_generic_ntp_egress_rules():
    """
    Create generic egress rules to allow access to any NTP server.
    :return:
    """

    rules = list()

    rules.append(create_iptables_udp_egress_ingress_rule(None, 123, Slots.ntp, transport=ipt.TRANSPORT_IPV4,
                                                         desc=u'all NTP Rule'))
    rules.append(create_iptables_udp_egress_ingress_rule(None, 123, Slots.ntp, transport=ipt.TRANSPORT_IPV6,
                                                         desc=u'all NTP Rule'))

    return rules


def create_iptables_ingress_rule_dest(ipaddr, port, protocol, slot, state, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create an ingress firewall rule for destination.
    :param ipaddr: Destination IP address, not host name.
    :param port: Destination port to use for connection
    :param protocol: protocol to use, IE: tcp, udp, icmp, ...
    :param slot: Firewall slot number
    :param state: state of iptables: NEW,ESTABLISHED,RELATED
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    if ipaddr:
        # Check transport version.
        transport = check_transport_value(ipaddr, transport)
    else:
        if transport == ipt.TRANSPORT_AUTO:
            raise ValueError('Unable to determine transport from ipaddr')

    if port:
        if port < 1 or port > 65536:
            raise ValueError('Invalid port value ({0}).'.format(port))

    if protocol not in [u'tcp', u'udp', u'icmp', u'udplite', u'esp', u'ah', u'sctp']:
        raise ValueError('Invalid protocol ({0}).'.format(protocol))

    if state:
        if state.strip().replace(u'NEW', '').replace(u'ESTABLISHED', '').replace(u'RELATED', '').replace(u',', ''):
            raise ValueError('Invalid Output State ({0}).'.state)
    else:
        raise ValueError('Output State is none.')

    if port:
        matches = [ipt.get_match(u'state', [ipt.get_jump_option(u'--state', state), ], ),
                   ipt.get_match(protocol, [ipt.get_match_option(u'--dport', port), ], ), ]
    else:
        matches = [ipt.get_match(u'state', [ipt.get_jump_option(u'--state', state), ], ), ]

    if ipaddr:
        rule = ipt.get_rule(ip_protocol_name=protocol, dest_address=ipaddr, matches=matches,
                            jump=ipt.get_jump(target=u'ACCEPT'))
    else:
        rule = ipt.get_rule(ip_protocol_name=protocol, matches=matches, jump=ipt.get_jump(target=u'ACCEPT'))

    return ipt.get_machine_subset(
        desc,
        slot,
        [
            ipt.get_chain(
                u'filter',
                [
                    ipt.get_ring(
                        u'input',
                        transport,
                        [
                            rule
                        ]
                    ),
                ]
            )
        ]
    )


def create_iptables_ingress_rule_source(ipaddr, port, protocol, slot, state, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create an ingress firewall rule for source.
    :param ipaddr: Source IP address, not host name.
    :param port: Source port to use for connection
    :param protocol: protocol to use, IE: tcp, udp, icmp, ...
    :param slot: Firewall slot number
    :param state: state of iptables: NEW,ESTABLISHED,RELATED
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    if ipaddr:
        # Check transport version.
        transport = check_transport_value(ipaddr, transport)
    else:
        if transport == ipt.TRANSPORT_AUTO:
            raise ValueError('Unable to determine transport from ipaddr')

    if port:
        if port < 1 or port > 65536:
            raise ValueError('Invalid port value ({0}).'.format(port))

    if protocol not in [u'tcp', u'udp', u'icmp', u'udplite', u'esp', u'ah', u'sctp']:
        raise ValueError('Invalid protocol ({0}).'.format(protocol))

    if state:
        if state.strip().replace(u'NEW', '').replace(u'ESTABLISHED', '').replace(u'RELATED', '').replace(u',', ''):
            raise ValueError('Invalid Output State ({0}).'.state)
    else:
        raise ValueError('Output State is none.')

    if port:
        matches = [ipt.get_match(u'state', [ipt.get_jump_option(u'--state', state), ], ),
                   ipt.get_match(protocol, [ipt.get_match_option(u'--sport', port), ], ), ]
    else:
        matches = [ipt.get_match(u'state', [ipt.get_jump_option(u'--state', state), ], ), ]

    if ipaddr:
        rule = ipt.get_rule(ip_protocol_name=protocol, source_address=ipaddr, matches=matches,
                            jump=ipt.get_jump(target=u'ACCEPT'))
    else:
        rule = ipt.get_rule(ip_protocol_name=protocol, matches=matches, jump=ipt.get_jump(target=u'ACCEPT'))

    return ipt.get_machine_subset(
        desc,
        slot,
        [
            ipt.get_chain(
                u'filter',
                [
                    ipt.get_ring(
                        u'input',
                        transport,
                        [
                            rule
                        ]
                    ),
                ]
            )
        ]
    )


def create_iptables_egress_rule_dest(ipaddr, port, protocol, slot, state, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create an egress firewall rule for destination.
    :param ipaddr: Destination IP address, not host name.
    :param port: Destination port to use for connection
    :param protocol: protocol to use, IE: tcp, udp, icmp, ...
    :param slot: Firewall slot number
    :param state: state of iptables: NEW,ESTABLISHED,RELATED
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    if ipaddr:
        # Check transport version.
        transport = check_transport_value(ipaddr, transport)
    else:
        if transport == ipt.TRANSPORT_AUTO:
            raise ValueError('Unable to determine transport from ipaddr')

    if port:
        if port < 1 or port > 65536:
            raise ValueError('Invalid port value ({0}).'.format(port))

    if protocol not in [u'tcp', u'udp', u'icmp', u'udplite', u'esp', u'ah', u'sctp']:
        raise ValueError('Invalid protocol ({0}).'.format(protocol))

    if state:
        if state.strip().replace(u'NEW', '').replace(u'ESTABLISHED', '').replace(u'RELATED', '').replace(u',', ''):
            raise ValueError('Invalid Output State ({0}).'.state)
    else:
        raise ValueError('Output State is none.')

    if port:
        matches = [ipt.get_match(u'state', [ipt.get_jump_option(u'--state', state), ], ),
                   ipt.get_match(protocol, [ipt.get_match_option(u'--dport', port), ], ), ]
    else:
        matches = [ipt.get_match(u'state', [ipt.get_jump_option(u'--state', state), ], ), ]

    if ipaddr:
        rule = ipt.get_rule(ip_protocol_name=protocol, dest_address=ipaddr, matches=matches,
                            jump=ipt.get_jump(target=u'ACCEPT'))
    else:
        rule = ipt.get_rule(ip_protocol_name=protocol, matches=matches, jump=ipt.get_jump(target=u'ACCEPT'))

    return ipt.get_machine_subset(
        desc,
        slot,
        [
            ipt.get_chain(
                u'filter',
                [
                    ipt.get_ring(
                        u'output',
                        transport,
                        [
                            rule
                        ]
                    ),
                ]
            )
        ]
    )


def create_iptables_egress_rule_source(ipaddr, port, protocol, slot, state, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create an egress firewall rule for source.
    :param ipaddr: Source IP address, not host name.
    :param port: Source port to use for connection
    :param protocol: protocol to use, IE: tcp, udp, icmp, ...
    :param slot: Firewall slot number
    :param state: state of iptables: NEW,ESTABLISHED,RELATED
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    if ipaddr:
        # Check transport version.
        transport = check_transport_value(ipaddr, transport)
    else:
        if transport == ipt.TRANSPORT_AUTO:
            raise ValueError('Unable to determine transport from ipaddr')

    if port:
        if port < 1 or port > 65536:
            raise ValueError('Invalid port value ({0}).'.format(port))

    if protocol not in [u'tcp', u'udp', u'icmp', u'udplite', u'esp', u'ah', u'sctp']:
        raise ValueError('Invalid protocol ({0}).'.format(protocol))

    if state:
        if state.strip().replace(u'NEW', '').replace(u'ESTABLISHED', '').replace(u'RELATED', '').replace(u',', ''):
            raise ValueError('Invalid Output State ({0}).'.state)
    else:
        raise ValueError('Output State is none.')

    if port:
        matches = [ipt.get_match(u'state', [ipt.get_jump_option(u'--state', state), ], ),
                   ipt.get_match(protocol, [ipt.get_match_option(u'--sport', port), ], ), ]
    else:
        matches = [ipt.get_match(u'state', [ipt.get_jump_option(u'--state', state), ], ), ]

    if ipaddr:
        rule = ipt.get_rule(ip_protocol_name=protocol, source_address=ipaddr, matches=matches,
                            jump=ipt.get_jump(target=u'ACCEPT'))
    else:
        rule = ipt.get_rule(ip_protocol_name=protocol, matches=matches, jump=ipt.get_jump(target=u'ACCEPT'))

    return ipt.get_machine_subset(
        desc,
        slot,
        [
            ipt.get_chain(
                u'filter',
                [
                    ipt.get_ring(
                        u'output',
                        transport,
                        [
                            rule
                        ]
                    ),
                ]
            )
        ]
    )


def create_iptables_tcp_egress_ingress_rule(ipaddr, port, slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create a TCP rule that allows external and internal access to the given addr and port.
    :param ipaddr: IP address, not host name.
    :param port: port to use for connection
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """
    return create_iptables_egress_ingress_rule(ipaddr, port, u'tcp', slot, transport, desc)


def create_iptables_udp_egress_ingress_rule(ipaddr, port, slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create a UDP rule that allows external and internal access to the given addr and port.
    :param ipaddr: IP address, not host name.
    :param port: port to use for connection
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """
    return create_iptables_egress_ingress_rule(ipaddr, port, u'udp', slot, transport, desc)


def create_iptables_egress_ingress_rule(ipaddr, port, protocol, slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create a rule that allows external and internal access to the given addr and port.
    Create a rule for client.
    :param ipaddr: IP address, not host name.
    :param port: port to use for connection
    :param protocol: protocol to use, IE: tcp, udp, icmp, ...
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    rules = list()

    rules.append(create_iptables_egress_rule_dest(ipaddr, port, protocol, slot, u'NEW,ESTABLISHED', transport, desc))
    rules.append(create_iptables_ingress_rule_source(ipaddr, port, protocol, slot, u'ESTABLISHED', transport, desc))

    return rules


def create_iptables_tcp_ingress_egress_rule(ipaddr, port, slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create a TCP rule that allows external and internal access to the given addr and port.
    :param ipaddr: IP address, not host name.
    :param port: port to use for connection
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """
    return create_iptables_ingress_egress_rule(ipaddr, port, u'tcp', slot, transport, desc)


def create_iptables_udp_ingress_egress_rule(ipaddr, port, slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create a UDP rule that allows external and internal access to the given addr and port.
    :param ipaddr: IP address, not host name.
    :param port: port to use for connection
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """
    return create_iptables_ingress_egress_rule(ipaddr, port, u'udp', slot, transport, desc)


def create_iptables_ingress_egress_rule(ipaddr, port, protocol, slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create a rule that allows internal and external access to the given addr and port.
    Create a rule for Server.
    :param ipaddr: IP address, not host name.
    :param port: port to use for connection
    :param protocol: protocol to use, IE: tcp, udp, icmp, ...
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    rules = list()

    rules.append(create_iptables_ingress_rule_dest(ipaddr, port, protocol, slot, u'NEW,ESTABLISHED', transport, desc))
    rules.append(create_iptables_egress_rule_source(ipaddr, port, protocol, slot, u'ESTABLISHED', transport, desc))

    return rules


def create_iptables_ingress_egress_forward_reject_rule(slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create an firewall rule for all reject in INPUT, OUTPUT and FORWARD chain by default.
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    rules = list()

    rules.append(create_iptables_ingress_reject_rule(slot, transport))
    rules.append(create_iptables_egress_reject_rule(slot, transport))
    rules.append(create_iptables_forward_reject_rule(slot, transport))

    return rules


def create_iptables_ingress_egress_reject_rule(slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create an firewall rule for all reject in INPUT, OUTPUT chain by default.
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    rules = list()

    rules.append(create_iptables_ingress_reject_rule(slot, transport))
    rules.append(create_iptables_egress_reject_rule(slot, transport))

    return rules


def create_iptables_ingress_reject_rule(slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create an firewall rule for all reject in INPUT chain by default.
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    if transport == ipt.TRANSPORT_AUTO:
        raise ValueError('Unable to determine transport')

    rule = ipt.get_rule(jump=ipt.get_jump(target=u'REJECT'))

    return ipt.get_machine_subset(
        desc,
        slot,
        [
            ipt.get_chain(
                u'filter',
                [
                    ipt.get_ring(
                        u'input',
                        transport,
                        [
                            rule
                        ]
                    ),
                ]
            )
        ]
    )


def create_iptables_egress_reject_rule(slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create an firewall rule for all reject in OUTPUT chain by default.
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    if transport == ipt.TRANSPORT_AUTO:
        raise ValueError('Unable to determine transport')

    rule = ipt.get_rule(jump=ipt.get_jump(target=u'REJECT'))

    return ipt.get_machine_subset(
        desc,
        slot,
        [
            ipt.get_chain(
                u'filter',
                [
                    ipt.get_ring(
                        u'output',
                        transport,
                        [
                            rule
                        ]
                    ),
                ]
            )
        ]
    )


def create_iptables_forward_reject_rule(slot, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create an firewall rule for all reject in FORWARD chain by default.
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    if transport == ipt.TRANSPORT_AUTO:
        raise ValueError('Unable to determine transport')

    rule = ipt.get_rule(jump=ipt.get_jump(target=u'REJECT'))

    return ipt.get_machine_subset(
        desc,
        slot,
        [
            ipt.get_chain(
                u'filter',
                [
                    ipt.get_ring(
                        u'forward',
                        transport,
                        [
                            rule
                        ]
                    ),
                ]
            )
        ]
    )


def create_iptables_remote_config(ipaddr, mask, port, protocol, slot, uid=None, gid=None, transport=ipt.TRANSPORT_AUTO,
                                  desc=''):
    """
    Create firewall rules for remote config.
    :param ipaddr: Destination IP address, not host name.
    :param mask: Netmask
    :param port: Destination port to use for connection
    :param protocol: protocol to use, IE: tcp, udp, icmp, ...
    :param slot: Firewall slot number
    :param transport: ipt.TRANSPORT_AUTO, ipt.TRANSPORT_IPV4 or ipt.TRANSPORT_IPV6
    :param desc: Extra description of the rule.
    :return:
    """

    rules = list()

    if ipaddr:
        # Check transport version.
        transport = check_transport_value(ipaddr, transport)
    else:
        if transport == ipt.TRANSPORT_AUTO:
            raise ValueError('Unable to determine transport from ipaddr')

    if mask:
        if transport == ipt.TRANSPORT_IPV4:
            if mask < 1 or mask > 32:
                raise ValueError('Invalid IPV4 mask value ({0}).'.format(mask))
        elif transport == ipt.TRANSPORT_IPV6:
            if mask < 1 or mask > 128:
                raise ValueError('Invalid IPV6 mask value ({0}).'.format(mask))

    if port:
        if port < 1 or port > 65536:
            raise ValueError('Invalid port value ({0}).'.format(port))

    if protocol not in [u'tcp', u'udp', u'icmp', u'udplite', u'esp', u'ah', u'sctp']:
        raise ValueError('Invalid protocol ({0}).'.format(protocol))

    dest_matches = list()
    dest_matches.append(ipt.get_match(u'state', [ipt.get_jump_option(u'--state', u'NEW,ESTABLISHED'), ], ))
    if port:
        dest_matches.append(ipt.get_match(protocol, [ipt.get_match_option(u'--dport', port), ], ))

    jump_options = list()
    if uid:
        jump_options.append(ipt.get_jump_option(u'--uid-owner', uid))

    if gid:
        jump_options.append(ipt.get_jump_option(u'--gid-owner', uid))

    if jump_options:
        dest_matches.append(ipt.get_match(u'owner', jump_options))

    if jump_options:
        rule = ipt.get_rule(ip_protocol_name=protocol, dest_address=ipaddr, dest_mask=mask, matches=dest_matches)
    else:
        rule = ipt.get_rule(ip_protocol_name=protocol, dest_address=ipaddr, dest_mask=mask, matches=dest_matches,
                            jump=ipt.get_jump(target=u'ACCEPT'))

    rules.append(
        ipt.get_machine_subset(
            desc,
            slot,
            [
                ipt.get_chain(
                    u'filter',
                    [
                        ipt.get_ring(
                            u'output',
                            transport,
                            [
                                rule
                            ]
                        ),
                    ]
                )
            ]
        )
    )

    source_matches = list()
    source_matches.append(ipt.get_match(u'state', [ipt.get_jump_option(u'--state', u'ESTABLISHED'), ], ))
    if port:
        source_matches.append(ipt.get_match(protocol, [ipt.get_match_option(u'--sport', port), ], ))

    rule = ipt.get_rule(ip_protocol_name=protocol, source_address=ipaddr, source_mask=mask, matches=source_matches,
                        jump=ipt.get_jump(target=u'ACCEPT'))

    rules.append(
        ipt.get_machine_subset(
            desc,
            slot,
            [
                ipt.get_chain(
                    u'filter',
                    [
                        ipt.get_ring(
                            u'input',
                            transport,
                            [
                                rule
                            ]
                        ),
                    ]
                )
            ]
        )
    )

    return rules
