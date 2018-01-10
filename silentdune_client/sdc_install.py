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

import argparse
import gettext
import logging
import operator
import os
import shutil
import shlex
import subprocess
import sys

from silentdune_client.modules import __load_modules__
from silentdune_client.utils.configuration import ClientConfiguration
from silentdune_client.utils.console import ConsoleBase
from silentdune_client.utils.log import setup_logging
from silentdune_client.utils.misc import is_service_running, node_info_dump, which
from silentdune_client.utils.node_info import NodeInformation

try:
    from configparser import ConfigParser  # noqa
except ImportError:
    # ver. < 3.0
    from ConfigParser import ConfigParser  # noqa

logging.basicConfig()
_logger = logging.getLogger('sd-client')


class Installer(ConsoleBase):

    # Modules dictionary list
    __modules = None
    __config = None

    # parser args
    args = None
    bad_arg = False

    node_info = None

    previous_firewall_service = None

    # Location of the installed service unit or script file.
    service_out_file = None

    def __init__(self, args, modules, node_info):

        self.__modules = modules
        self.args = args
        self.node_info = node_info
        self.__config = ClientConfiguration()

    def write_config(self):
        """
        Loop through the modules to set their configuration file items and then save the configuration.
        """

        for mod in self.__modules:
            result = mod.prepare_config(self.__config)

            if result is False:  # If prepare_config() returns None, we just want to continue.
                _logger.error('Preparing configuration file items failed in module {0}.'.format(mod.get_name()))
                return False

        # Write the configuration file out.
        return self.__config.write_config()

    def install_service(self):
        """
        Based on everything we know, lets install the init service.
        :return: True if successful, otherwise False.
        """

        self.cwrite('Configuring Silent Dune firewall service...')

        # Figure out our path
        base_path = os.path.split(os.path.realpath(__file__))[0]

        systemd_in_file = os.path.join(base_path, 'init/sdc-firewall.systemd.in')
        init_in_file = os.path.join(base_path, 'init/sdc-firewall.sysv.in')

        # Check and make sure we can find the init scripts.
        if not os.path.exists(systemd_in_file) or \
                not os.path.exists(init_in_file):
            _logger.critical('Unable to find init service files.')
            return False

        firewall_exec = which('sdc-firewall')

        if not firewall_exec:
            self.cwriteline('[Error]', 'Unable to locate our firewall executable.')
            return False

        # Install systemd service file.
        if self.node_info.sysd_installed:

            path = None

            # Determine systemd service unit install directory.
            if os.path.exists('/usr/lib/systemd/system/'):  # Redhat based
                path = '/usr/lib/systemd/system/'
            elif os.path.exists('/lib/systemd/system/'):  # Ubuntu based
                path = '/lib/systemd/system/'
            elif os.path.exists('/etc/systemd/system/'):  # Last resort location
                path = '/etc/systemd/system/'

            if not path:
                self.cwriteline('[Error]', 'Unable to locate systemd service unit path.')
                return False

            self.service_out_file = os.path.join(path, 'sdc-firewall.service')

            # See if we need to copy the service unit file to the destination
            if not os.path.isfile(self.service_out_file):
                shutil.copy(systemd_in_file, self.service_out_file)
                os.chmod(self.service_out_file, 0o644)

        if self.node_info.sysv_installed:

            # http://askubuntu.com/questions/2263/chkconfig-alternative-for-ubuntu-server
            path = '/etc/init.d/'
            self.service_out_file = os.path.join(path, 'sdc-firewall')

            # See if we need to copy the service unit file to the destination
            if not os.path.isfile(self.service_out_file):
                shutil.copy(init_in_file, self.service_out_file)
                os.chmod(self.service_out_file, 0o755)

        # Enable service
        # if not self.node_info.enable_service('sdc-firewall'):
        #    self.cwriteline('[Error]', 'Firewall service failed to enable.')
        #    return False

        # Start service
        # if not self.node_info.start_service('sdc-firewall'):
        #     self.cwriteline('[Error]', 'Firewall service failed to start.')
        #     return False

        self.cwriteline('      [OK]', 'Firewall service installed. Please start "sdc-firewall" service now.')

        return True

    def remove_service(self):

        # Remove the systemd service file.
        if self.node_info.sysd_installed:

            if is_service_running('sdc-firewall'):
                if not self.node_info.stop_service('sdc-firewall'):
                    _logger.debug('Firewall service failed to stop.')

                if not self.node_info.disable_service('sdc-firewall'):
                    _logger.debug('Unable to disable firewall service.')

            if os.path.exists(self.service_out_file):
                os.remove(self.service_out_file)

        if self.node_info.sysv_installed:
            # TODO: Write the sysv service removal code.
            pass

        self.cwriteline('[OK]', 'Firewall service removed.')

    def disable_previous_firewall(self):
        """
        Disable the previous firewall service.
        :return: True if successful, otherwise False.
        """

        if not self.node_info.previous_firewall_service or self.node_info.previous_firewall_service == 'sdc-firewall':
            return True

        # Check to see if the previous firewall service is running.
        if not is_service_running(self.node_info.previous_firewall_service):
            _logger.info('The current firewall service does not seem to be running.')
            return True

        self.cwrite('Stopping the current firewall service...')

        # Stop and Disable the previous firewall service.
        if not self.node_info.stop_service(self.node_info.previous_firewall_service):
            self.cwriteline('[Error]', 'Unable to stop the current firewall service.')
            return False

        self.cwriteline('[OK]', 'Successfully stopped the current firewall service.')

        self.cwrite('Disabling the current firewall service...')

        if not self.node_info.disable_service(self.node_info.previous_firewall_service):
            self.cwriteline('[Error]', 'Unable to disable the current firewall service.')
            return False

        self.cwriteline('[OK]', 'Successfully disabled the current firewall service.')

        return True

    def clean_up(self):
        """
        Use this method to clean up after a failed install
        """
        self.cwrite('Cleaning up...')

        # # The following code can only run if we are running under privileged account.
        # if self.node_info.root_user:
        #
        #     # Remove our firewall service.
        #     self.remove_service()
        #
        #     # Remove the directories the daemon process uses.
        #     self.__config.delete_directories()
        #     _logger.debug('Removed daemon process directories.')
        #
        #     # Remove the system user the daemon process uses.
        #     self.__config.delete_user()
        #     _logger.debug('Removed daemon process system user.')
        #
        #     # Check to see if the previous firewall service is running or not
        #     if self.node_info.previous_firewall_service:
        #         if not is_service_running(self.node_info.previous_firewall_service):
        #             self.node_info.enable_service(self.node_info.previous_firewall_service)
        #             self.node_info.start_service(self.node_info.previous_firewall_service)
        #
        #     # if we are running as root, delete the configuration directory
        #     if self.node_info.config_root is not None \
        #             and os.path.exists(self.node_info.config_root) \
        #             and os.path.realpath(self.node_info.config_root) != '/':
        #         rmdir(self.node_info.config_root)

        self.cwriteline('[OK]', 'Finished cleaning up.')

    def start_install(self):
        """
        Begin installing the Silent Dune Client.
        """

        # If this node is running systemd, remove the pidfile setting.
        if self.node_info.sysd_installed:
            self.__config.delete('settings', 'pidfile')

        # Check to see that the NodeInformation information gathering was successful.
        if self.node_info.error:
            _logger.error('Gathering information about this node failed.')
            return False

        # See if we haven't determined the configuration root directory.
        if not self.node_info.config_root:
            _logger.error('Error determining the configuration root directory.')
            return False

        # if self.node_info.previous_firewall_service == 'sdc-firewall':
        #     self.cwriteline('[Error]', 'Silent Dune firewall service is already running, please uninstall first.')
        #     return False

        #
        # Have each module do their pre install work now.
        #
        for mod in self.__modules:
            result = mod.pre_install()
            if result is not None and result is False:
                return False

        # The following code can only run if we are running under privileged account.
        if self.node_info.root_user:

            # # Create the daemon process user
            # if not self.__config.create_service_user():
            #     return False

            # Create the directories the daemon process uses.
            if not self.__config.create_directories():
                return False

        #
        # Have each module do their install work now.
        #
        for mod in self.__modules:
            result = mod.install_module()
            if result is not None and result is False:
                return False

        # The following code can only run if we are running under privileged account.
        if self.node_info.root_user:

            # Disable the current firewall service
            if self.node_info.previous_firewall_service:
                if not self.disable_previous_firewall():
                    return False

        if not self.write_config():
            return False

        # Have each module do their post install work now.
        for mod in self.__modules:
            result = mod.post_install()
            if result is not None and result is False:
                return False

        # Finally install the firewall service.
        if self.node_info.root_user:

            if not self.install_service():
                return False

            self.node_info.restorecon('/etc/silentdune')

            if not os.path.isdir('/var/run/silentdune'):
                os.makedirs('/var/run/silentdune')

            self.node_info.restorecon('/var/run/silentdune')

        return True


def run():

    # Set global debug value and setup application logging.
    setup_logging(_logger, '--debug' in sys.argv)

    # See if we need to dump information about this node.
    if '--debug' in sys.argv:
        node_info_dump(sys.argv)

    # Get the path where this file is located.
    app_path = os.path.split(os.path.realpath(__file__))[0]
    # Get our package path and package name
    base_path, package_name = os.path.split(app_path)

    # Check and make sure we can find the init scripts.
    if not os.path.exists(os.path.join(app_path, 'init/sdc-firewall.systemd.in')) or \
            not os.path.exists(os.path.join(app_path, 'init/sdc-firewall.sysv.in')):
        print('sdc-install: error: Unable to locate client init scripts, unable to install')
        sys.exit(1)

    # Setup i18n - Good for 2.x and 3.x python.
    kwargs = {}
    if sys.version_info[0] < 3:
        kwargs['unicode'] = True
    gettext.install('sdc_install', **kwargs)

    # Get loadable module list
    module_list = __load_modules__(base_path=base_path)

    # Sort modules by the priority attribute.
    module_list = sorted(module_list, key=operator.attrgetter('priority'))

    # Setup program arguments.
    parser = argparse.ArgumentParser(prog='sdc-install')
    parser.add_argument(_('--debug'), help=_('Enable debug output'), default=False, action='store_true')  # noqa

    # Loop through the module objects and add any argparse arguments.
    for mod in module_list:
        mod.add_installer_arguments(parser)

    args = parser.parse_args()

    # Have each module validate arguments.
    for mod in module_list:
        if mod.validate_arguments(args) is False:  # If return value is None, we just want to continue.
            parser.print_help()
            exit(1)

    node_info = NodeInformation(console_debug=('--debug' in sys.argv))

    # Instantiate the installer object
    i = Installer(args, module_list, node_info)

    # Begin the install process.
    if not i.start_install():

        # Have each module do their uninstall work now.
        for mod in module_list:
            mod.uninstall_module()

        _logger.error('Install aborted.')
        return 1

    return 0


# --- Main Program Call ---
if __name__ == '__main__':
    sys.exit(run())
