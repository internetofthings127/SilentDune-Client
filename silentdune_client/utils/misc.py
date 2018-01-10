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

import logging
import os
import platform
import shutil
import socket
import subprocess
import sys

_logger = logging.getLogger('sd-client')


def which(program):
    """
    Find the path for a given program
    http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
    """

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


def node_info_dump(args):
    """
    Output information about this machine.
    """
    # Basic system detections
    print('System = {0}'.format(platform.system()))

    # Current distribution
    print('Distribution = {0}'.format(platform.dist()[0]))
    print('Distribution Version = {0}'.format(platform.dist()[1]))

    # Python version
    print('Python Version: {0}'.format(sys.version.replace('\n', '')))

    print(args)


def rmdir(path):
    """
    Safely delete a path, make sure its not the filesystem root.
    :param path:
    :return:
    """
    if not path:
        return False

    path = os.path.realpath(path)

    if os.path.exists(path) and path != '/':
        shutil.rmtree(path)

    return True


def determine_config_root():
    """
    Determine where we are going to write the SD node configuration file.
    """

    home = os.path.expanduser('~')
    root_failed = False
    home_failed = False

    config_root = '/etc/silentdune/'

    # Check to see if the path already exist, if it does just return.
    if os.path.exists(config_root):
        return config_root

    # Test to see if we are running as root
    if os.getuid() == 0:
        test_file = os.path.join(config_root, 'test.tmp')

        try:
            os.makedirs(config_root)
            h = open(test_file, 'w')
            h.close()

            rmdir(config_root)

        except OSError:
            root_failed = True

    else:
        root_failed = True

    # If root access has failed, try the current user's home directory
    if root_failed:
        config_root = os.path.join(home, '.silentdune')

        # Check to see if the path already exist, if it does just return.
        if os.path.exists(config_root):
            return config_root

        test_file = os.path.join(config_root, 'test.tmp')

        try:
            os.makedirs(config_root)
            h = open(test_file, 'w')
            h.close()

            rmdir(config_root)

        except OSError:
            home_failed = True

    # Check if both locations failed.
    if root_failed and home_failed:
        _logger.critical('Unable to determine a writable configuration path for this node.')
        return None

    return config_root


def get_init_system():
    """
    Return the active init system on this node.
    :return:
    """
    # See if this system is an upstart setup.
    if which('initctl') is not None and os.path.isfile(which('initctl')):
        return 'upstart'

    # See if this system is a systemd setup.
    if which('systemctl') is not None and os.path.exists('/run/systemd/system'):
        return 'systemd'

    # See if this system is a sysvinit setup, must be after upstart and systemd detection.
    if which('service') is not None:
        return 'sysv'

    return None


def is_service_running(name):
    """
    Determine if the the specified service is running or active
    :param name:
    :return:
    """

    init = get_init_system()

    cmd = ['service', name, 'status']

    if init == 'systemd':
        cmd = ['systemctl', 'status', name]

    with open(os.devnull, 'w') as FNULL:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=FNULL)
        stdoutdata, stderrdata = p.communicate()
        p.wait()

    if stderrdata is None:
        data = stdoutdata.decode('utf-8')
        if init == 'systemd' and 'Active: active' in data:
            return True
        elif 'running' in data:
            return True

    return False


def get_active_firewall():
    """
    Determine which firewall service is running on this system.
    :return: Firewall service name
    """
    if is_service_running('ufw'):
        return 'ufw'

    if is_service_running('firewalld'):
        return 'firewalld'

    if is_service_running('iptables'):
        return 'iptables'

    if is_service_running('sdc-firewall'):
        return 'sdc-firewall'

    return None


# http://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
def is_valid_ipv4_address(address):
    """
    Validate an IPv4 IP address.
    :param address: IPv4 address with no netmask.
    :return: True if valid IPv4 IP address.
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def is_valid_ipv6_address(address):
    """
    Validate an IPv6 IP address.
    :param address: IPv6 address with no netmask.
    :return: True if valid IPv6 IP address.
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def validate_network_address(address):
    """
    Parse the network string for valid network address.
    :param address: Single or space delimited list of ipaddr/netmask values.
    :return: True if valid or False if incorrectly formatted.
    """

    if not address:
        return False

    for cidr in address.split(' '):

        try:
            ipaddr, bits = cidr.split('/')

            if '.' in bits and bits.count('.') == 3:  # See if we need to convert long notation to cidr notation.
                netmask = bits.split('.')
                binary_str = ''
                for octet in netmask:
                    if 0 <= int(octet) <= 255:
                        binary_str += bin(int(octet))[2:].zfill(8)
                    else:
                        return False
                bits = str(len(binary_str.strip('0')))

            bits = int(bits)

            if is_valid_ipv4_address(ipaddr) and 0 <= bits <= 32:
                continue

            if is_valid_ipv6_address(ipaddr) and 0 <= bits <= 128:
                continue

            return False

        except ValueError:
            return False

    return True
