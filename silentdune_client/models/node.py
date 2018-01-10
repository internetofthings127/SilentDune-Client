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


class Node(JsonObject):
    """
    Represents the NodeSerializer json schema
    """
    id = None  # PK value
    platform = None  # Firewall platform, IE: iptables
    os = None  # System, IE: linux, windows, macos, freebsd, netbsd.
    dist = None  # Distribution Name.
    dist_version = None  # Distribution Version.
    hostname = None
    python_version = None
    machine_id = None  # Unique machine ID.
    last_connection = None  # Last connection datetime stamp.
    sync = None  # True if node needs to download new rule bundleset and update its information on the server.
    notes = None  # Notes about this node
    active = None  # Node firewall is actively running.
    locked = None  # Node should be in locked down or not.
    polling_interval = None  # A numeric value representing the number of minutes the node should check the server.
    fernet_key = None  # A fernet encryption key.


class NodeBundle(JsonObject):
    """
    Represents the NodeBundleSerializer json schema
    """
    id = None  # PK value
    node = None  # Node ID value
    bundle = None  # Bundle ID value


class NodeProcess(JsonObject):
    """
    Represents the NodeProcessSerializer json schema
    """
    id = None  # PK value
    node = None  # Node ID value
    name = None  # Process name from ps -ef
    category = None  # Process category name. IE: PostgreSQL Service, Apache Service.
    running = None  # True/False
    runningfor = None  # Process up time.
    ipaddr = None  # Bound IP addresses or 'all' for all available addresses.
    port = None  # Bound port number or range.
    lockable = None  # Firewall access rules can be removed to prevent traffic from reaching service.
    locked = None  # Firewall rules are removed for this process.
    delete = None  # This process database record is ready for deletion.

