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
from silentdune_client.utils.misc import validate_network_address


class IPAddressValidationTest(TestCase):

    def test_network_addresses(self):

        assert validate_network_address('10.0.0.0/255.255.255.255')
        assert validate_network_address('10.0.0.0/32')

        assert not validate_network_address('10.0.0.0/255.255.255.256')
        assert not validate_network_address('10.0.0.0/33')

        assert validate_network_address('10.0.0.0/0.0.0.0')
        assert not validate_network_address('10.0.0.0/0.0.0')

        assert validate_network_address('127.0.0.1/255.0.0.0')
        assert validate_network_address('10.0.0.0/8')

        assert validate_network_address('::1/128')

        assert not validate_network_address('::1/129')

        # Check multiple values.
        assert validate_network_address('10.0.0.0/255.255.255.255 20.0.0.0/255.255.255.255')
        assert validate_network_address('10.0.0.0/24 20.0.0.0/24')
        assert validate_network_address('10.0.0.0/24 20.0.0.0/24 127.0.0.1/8 ::1/128')
