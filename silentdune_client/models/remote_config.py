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

from silentdune_client.models.json_base import JsonObject


class RemoteConfig(JsonObject):

    schema_version = None  # Should be 1 for now.
    hash_method = None  # Hashing method to use in verification, IE: SHA1, SHA256, ...
    rules = None  # Array of RemoteConfigRule objects

    def __init__(self, *args, **kwargs):
        super(RemoteConfig, self).__init__(args[0], kwargs)

        if self.schema_version == 1:
            self.rules = self.dict_to_obj_array(RemoteConfigRule_v1, self.rules)


class RemoteConfigRule_v1(JsonObject):

    host = None  # single IPv4 or IPv6 destination host
    mask = None  # netmask for host
    port = None  # destination network port
    protocol = None  # tcp, udp, icmp, ...
    uid = None  # for match "owner". IE: "-m owner --uid-owner 123"
    gid = None  # for match "owner". IE: "-m owner --gid-owner 123"
