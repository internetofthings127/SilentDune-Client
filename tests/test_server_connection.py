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

# try:
#     from unittest import mock  # <- Python 3.x
# except ImportError:
#     import mock

from silentdune_client.modules.comm.sd_server.connection import ConnStatus
from tests.mock_server import BaseServerPasswordConnection


class ServerConnectionTest(BaseServerPasswordConnection):

    def test_connect_with_password(self):
        """ Make sure the base class server connection was successful """
        assert self.sdc.status == ConnStatus.authenticated


# TODO: sdc.connect_with_machine_id('452e2db3574f473e98dd166365722d77')
