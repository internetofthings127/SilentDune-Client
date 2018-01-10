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

from enum import IntEnum


class Slots(IntEnum):
    """ Slot numbers for known rule sets """
    loopback = 0
    admin = 110
    silentdune_server = 120
    dns = 130
    ntp = 140
    updates = 150
    identity = 160
    dhcp = 170
    icmp = 180
    network_iso = 500  # Network isolation rules
    rc_access = 600  # accessing remote config
    rc_apply = 610  # applying remote config
    logging = 9800
    reject = 9900
