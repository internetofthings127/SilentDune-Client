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

from datetime import datetime
from dateutil.tz import tzlocal
import logging
import re

from silentdune_client.utils.node_info import NodeInformation
from silentdune_client.models.json_base import JsonObject

_logger = logging.getLogger('sd-client')


# TODO: Create IP6LogEvent object
class IPLogEvent(JsonObject):
    """
    Kernel Firewall Log Event record
    based off iptables log format information found here:
        http://search.cpan.org/~paulv/POE-Filter-Log-IPTables-0.02/IPTables.pm
        src: kernel-3.10.0-514.2.2.el7/linux-3.10.0-514.2.2.el7.x86_64/net/ipv4/netfilter/nf_log_ipv4.c
        src: kernel-3.10.0-514.2.2.el7/linux-3.10.0-514.2.2.el7.x86_64/net/ipv6/netfilter/nf_log_ipv6.c
    """
    event = None  # Unmodified log event string
    node = None  # Node ID value
    event_flag = None  # Our log event prefix value, usually set by the server module.  Must start with 'SDC'.

    # Top level event structure
    event_dt = None  # Timestamp of packet
    tz_offset = None  # Timezone offset from GMT in "-+00:00" format.
    iface_in = None  # Interface In - Packet received on.
    iface_out = None  # Interface Out - Packet sent on.
    src_addr = None  # Source IP Address
    dest_addr = None  # Destination IP address
    length = None  # Packet length
    tos = None  # Type of Service
    prec = None  # Precedence
    ttl = None  # Packet Time to Live value.
    packet_id = None  # Packet ID
    frag_flags = None  # Can have "CE" (congestion), "DF" (don't fragment), or "MF" (more fragments are coming).
    protocol = None  # 'tcp', 'udp', 'icmp', or a number corresponding to the protocol in /etc/protocols.

    # Event values based on protocol value.
    # TCP and UDP
    src_port = None  # Source port
    dest_port = None  # Destination port

    # TCP only
    window = None  # Length of the tcp window.
    reserved = None  # Reserved bits.
    urgp = None  # The urgent pointer.
    tcp_flags = None  # "CWR" (Congestion Window Reduced), "ECE" (Explicit Congestion Notification Echo),
    # "URG" (Urgent), "ACK" (Acknowledgement), "PSH" (Push), "RST" (Reset), "SYN" (Synchronize), or "FIN" (Finished)

    # UDP only
    udp_length = None  # length of the UDP packet.

    # ICMP
    icmp_type = None  # For ICMP this is a numeric value,
    icmp_code = None  # Numeric code of the ICMP packet.
    icmp_id = None  # ID of the ICMP echo packet.
    icmp_seq = None  # Sequence of the ICMP packet.
    icmp_error_header = None  # Some types of ICMP - 3 (destination unreachable), 4 (source quench), and
    # 11 (time exceeded) contain the IP and protocol headers that generated the ICMP packet.
    # This will be a IPLogEvent object.

    parent_id = None  # Points to the parent record when there is an ICMP child data record.

    leftover = ''  # Left over log event text that was not used during parsing.

    def __init__(self, event):
        self.frag_flags = []
        self.tcp_flags = []

        self.event = event
        self._parse()

    def __str__(self):
        return self.event

    def _parse(self):

        if NodeInformation.platform == 'linux':
            return self._parse_linux()

        raise ValueError('IPLogEvent Parser: os platform not supported.')

    def _parse_linux(self):

        p = self.event

        # Look for embedded packet event log first.
        if '[' in p:
            try:
                imbed_p = p[p.index('['):p.rindex(']') + 1]
                p = p.replace(imbed_p, '')
                imbed_p = imbed_p[1:-1].strip()  # Remove braces
                self.icmp_error_header = IPLogEvent(imbed_p)  # Recursively parse this packet
            except ValueError:
                raise
                pass

        # Retrieve the timestamp and remove it from the event data.
        if 'kernel:' in p:
            # Get the timestamp
            ts = p[:p[:p.index('kernel:')].strip().rindex(' ')]
            p = p.replace(ts, '')
            self.event_dt = datetime.strptime(ts, '%b %d %H:%M:%S').replace(year=datetime.now().year,
                                                                            tzinfo=tzlocal()).isoformat()
            offset = re.search('(Z|(\+|-)[0-9][0-9]:[0-9][0-9])$', self.event_dt)
            if offset:
                self.tz_offset = offset.group(0)

            # Remove the system name and the 'kernel:' text.
            p = p[p.index(':') + 1:].strip()

            # Capture the log record type flag.
            self.event_flag = p[:p.index(':')]
            p = p.replace(self.event_flag + ':', '').strip()

        # parse event log key value pairs.
        p, self.iface_in = self._parse_event_key_value(p, 'IN')
        p, self.iface_out = self._parse_event_key_value(p, 'OUT')
        p, self.src_addr = self._parse_event_key_value(p, 'SRC')
        p, self.dest_addr = self._parse_event_key_value(p, 'DST')
        p, self.length = self._parse_event_key_value(p, 'LEN')
        p, self.tos = self._parse_event_key_value(p, 'TOS')
        p, self.prec = self._parse_event_key_value(p, 'PREC')
        p, self.ttl = self._parse_event_key_value(p, 'TTL')
        p, self.packet_id = self._parse_event_key_value(p, 'ID')
        p, self.protocol = self._parse_event_key_value(p, 'PROTO')

        if self.protocol == 'TCP':
            p, self.window = self._parse_event_key_value(p, 'WINDOW')
            p, self.reserved = self._parse_event_key_value(p, 'RES')
            p, self.urgp = self._parse_event_key_value(p, 'URGP')
            p, self.src_port = self._parse_event_key_value(p, 'SPT')
            p, self.dest_port = self._parse_event_key_value(p, 'DPT')

        if self.protocol == 'UDP':
            p, self.udp_length = self._parse_event_key_value(p, 'LEN')
            p, self.src_port = self._parse_event_key_value(p, 'SPT')
            p, self.dest_port = self._parse_event_key_value(p, 'DPT')

        if self.protocol == 'ICMP':
            p, self.icmp_code = self._parse_event_key_value(p, 'CODE')
            p, self.icmp_seq = self._parse_event_key_value(p, 'SEQ')
            p, self.icmp_type = self._parse_event_key_value(p, 'TYPE')
            p, self.icmp_id = self._parse_event_key_value(p, 'ID')

        if self.protocol == 'TCP':
            p, self.tcp_flags = self._parse_event_flags(p, self.tcp_flags, 'CWR')
            p, self.tcp_flags = self._parse_event_flags(p, self.tcp_flags, 'ECE')
            p, self.tcp_flags = self._parse_event_flags(p, self.tcp_flags, 'URG')
            p, self.tcp_flags = self._parse_event_flags(p, self.tcp_flags, 'ACK')
            p, self.tcp_flags = self._parse_event_flags(p, self.tcp_flags, 'PSH')
            p, self.tcp_flags = self._parse_event_flags(p, self.tcp_flags, 'RST')
            p, self.tcp_flags = self._parse_event_flags(p, self.tcp_flags, 'SYN')
            p, self.tcp_flags = self._parse_event_flags(p, self.tcp_flags, 'FIN')

        # parse event log fragment flags
        p, self.frag_flags = self._parse_event_flags(p, self.frag_flags, 'CE')
        p, self.frag_flags = self._parse_event_flags(p, self.frag_flags, 'DF')
        p, self.frag_flags = self._parse_event_flags(p, self.frag_flags, 'MF')

        # Save any unhandled event text.
        self.leftover = p.strip()

    def _parse_event_key_value(self, p, key):
        """
        Return the Key value and remove the Key Value from the string parameter.
        Only looks at and removes the first occurrence of a Key.  Some key names are duplicated in an event.
        """
        key += '='
        p += ' '  # Add a space at the end in case the key is the last element.
        try:
            s = p[p.index(key):p[p.index(key):].index(' ') + p.index(key)]
            v = s.split('=')[1]
            return p.replace(s, '').replace('  ', ' ').strip(), v if v else None
        except ValueError:
            if key == 'SRC':
                raise
            pass

        return p, None

    def _parse_event_flags(self, p, l, flag):
        """
        Look for the flag in the event data, remove if found and add to list object.
        :param p: Event data
        :param l: List object
        :param flag: Flag to search for.
        :return: Event data, list
        """
        if flag in p:
            l.append(flag)
            p = p.replace(flag, '').replace('  ', ' ').strip()

        return p, l
