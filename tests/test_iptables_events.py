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

from unittest import TestCase
try:
    from unittest import mock
except ImportError:
    import mock

from silentdune_client.models.iptables_log_event import IPLogEvent

from tests.mock_server import mock_server_requests_get, mock_server_requests_post, BaseServerPasswordConnection

data = [
    'Jun 17 14:11:08 test kernel: SDC: IN= OUT=eth0 SRC=10.90.0.71 DST=10.90.0.10 LEN=432 TOS=0x10 PREC=0x00 TTL=64 ID=18915 DF PROTO=TCP SPT=22 DPT=37126 WINDOW=912 RES=0x00 ACK PSH URGP=0',  # noqa
    'Nov 28 11:17:33 test kernel: SDC: IN=ppp0 OUT= SRC=192.168.2.113 DST=192.168.0.223 LEN=492 TOS=0x00 PREC=0x00 TTL=240 ID=39184 PROTO=ICMP TYPE=3 CODE=3 [SRC=192.168.0.223 DST=192.168.2.113 LEN=464 TOS=0x00 PREC=0x00 TTL=52 ID=58665 DF PROTO=TCP SPT=34373 DPT=80 WINDOW=63712 RES=0x00 ACK PSH FIN URGP=0 ]',  # noqa
    'Nov 30 09:54:51 test kernel: SDC: IN=ppp0 OUT= SRC=10.90.0.34 DST=192.168.143.41 LEN=37 TOS=0x00 PREC=0x00 TTL=115 ID=61772 PROTO=ICMP TYPE=8 CODE=0 ID=256 SEQ=8403',  # noqa
    'Nov 29 10:52:11 test kernel: SDC: IN=eth1 OUT= SRC=10.9.8.46 DST=192.168.0.208 LEN=801 TOS=0x00 PREC=0x00 TTL=115 ID=3391 PROTO=UDP SPT=31466 DPT=1026 LEN=781',  # noqa
    'Nov 28 19:52:19 test kernel: SDC: IN=eth1 OUT= SRC=192.168.1.31 DST=192.168.0.54 LEN=100 TOS=0x00 PREC=0x00 TTL=63 ID=38565 DF PROTO=TCP SPT=25 DPT=1071 WINDOW=57352 RES=0x00 ACK PSH URGP=0',  # noqa
    'Jun 20 13:19:14 test kernel: SDC: IN= OUT=eth0 SRC=10.90.0.71 DST=10.90.0.10 LEN=52 TOS=0x10 PREC=0x00 TTL=64 ID=64259 DF PROTO=TCP SPT=22 DPT=46306 WINDOW=787 RES=0x00 ACK URGP=0',  # noqa
    'Jun 20 13:18:54 test kernel: SDC: IN= OUT=eth0 SRC=10.90.0.71 DST=4.2.2.2 LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=19348 DF PROTO=ICMP TYPE=8 CODE=0 ID=8756 SEQ=2'  # noqa
]

icmp_error_data = 'Nov 28 11:17:33 test kernel: SDC: IN=ppp0 OUT= SRC=192.168.2.113 DST=192.168.0.223 LEN=492 TOS=0x00 PREC=0x00 TTL=240 ID=39184 PROTO=ICMP TYPE=3 CODE=3 [SRC=192.168.0.223 DST=192.168.2.113 LEN=464 TOS=0x00 PREC=0x00 TTL=52 ID=58665 DF PROTO=TCP SPT=34373 DPT=80 WINDOW=63712 RES=0x00 ACK PSH FIN URGP=0 ]'  # noqa


class LogEventTest(TestCase):

    def test_event_log_parsing(self):
        """
        Test that the IPLogEvent parsing succeeds.
        """
        for item in data:
            obj = IPLogEvent(item)

            assert obj.src_addr
            assert obj.dest_addr
            assert obj.ttl
            assert obj.length

            assert obj.protocol in ['TCP', 'UDP', 'ICMP']

            if obj.protocol == 'TCP' or obj.protocol == 'UDP':
                assert obj.src_port
                assert obj.dest_port

            if obj.protocol == 'UDP':
                assert obj.udp_length

            if obj.protocol == 'ICMP':

                assert obj.icmp_type
                assert obj.icmp_code

                if obj.icmp_error_header is not None:

                    assert obj.icmp_error_header.protocol
                    assert obj.icmp_error_header.src_addr
                    assert obj.icmp_error_header.dest_addr
                    assert obj.icmp_error_header.length


class ServerEventTest(BaseServerPasswordConnection):

    @mock.patch('silentdune_client.modules.comm.sd_server.connection.requests.get', autospec=True,
                side_effect=mock_server_requests_get)
    @mock.patch('silentdune_client.modules.comm.sd_server.connection.requests.post', autospec=True,
                side_effect=mock_server_requests_post)
    def test_event_server_post(self, mock_get, mock_post):

        obj = IPLogEvent(data[0])
        id, code = self.sdc.iptables_send_alert(obj)

        assert id == 55
        assert code == 201

        obj = IPLogEvent(icmp_error_data)

        id, code = self.sdc.iptables_send_alert(obj)

        assert id == 55
        assert code == 201
