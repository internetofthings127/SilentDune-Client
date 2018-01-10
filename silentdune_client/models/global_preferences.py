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


class GlobalPreferences(JsonObject):
    """
    Represents the NodeBundleSerializer json schema
    """
    # Server API fields
    lockdown_slot_level = None  # Represents the maximum slot level that should be used during lock down mode.
    polling_interval = None  # The global setting for node polling interval.

    # Built in fields
    rejection_slot_level = 9900  # Represents the rejection rules slot level, these are not filtered during lock down.
