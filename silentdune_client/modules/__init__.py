#
# Authors: Robert Abram <robert.abram@entpack.com>,
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
import time

from silentdune_client.utils.node_info import NodeInformation
from silentdune_client.utils.console import ConsoleBase
from silentdune_client.utils.module_loading import import_by_str
from silentdune_client.utils.exceptions import ModuleLoadError

_logger = logging.getLogger('sd-client')

# Parent to Child task queue IDs
TASK_STOP_PROCESSING = 0


class QueueTask(object):
    """
    The QueueTask object is an object to be passed between the parent processing thread
    and the module processing threads.  Allows for back and forth communication along with
    passing tasks between module processing threads.
    """

    _task_id = None  # One of the TASK id value from above.
    _trans_id = None  # ID used by the source to track messages.
    _src_module = None  # Source module name
    _dest_module = None  # Destination module name
    _data = None  # Data for this task.

    def __init__(self, task_id, src_module=None, dest_module=None, data=None, trans_id=None, ):
        self._task_id = task_id
        self._src_module = src_module
        self._dest_module = dest_module
        self._data = data
        self._trans_id = trans_id

    def get_task_id(self):
        return self._task_id

    def get_sender(self):
        return self._src_module

    def get_trans_id(self):
        return self._trans_id

    def get_dest_name(self):
        return self._dest_module

    def get_data(self):
        return self._data


class BaseModule(ConsoleBase):
    """
    This is the Virtual module object every module should inherit from.
    Each property and method are virtual and can be overridden as needed.
    """

    # The name of the module and version.
    # _name = 'UnknownModule'
    _arg_name = 'unknown'  # This is the argparser name for this module
    _config_section_name = 'unknown'  # This is the configuration file section name
    _version = '0.0.1'
    _enabled = True

    # Multi thread processing properties
    wants_processing_thread = False  # Set this to true if your module will use a child processing thread.

    # Parent process management queue.  This is only valid if we are using a processing thread.
    _mqueue = None

    # List of loaded module names, useful to see if another module has been loaded.
    _mlist = None

    # Delay in seconds to wait for a message from the parent.  After timeout has expired, process_loop is called.
    _queue_timeout = 1.0  # Min = 0.01, Max = 10.0.

    # _start_t and _seconds_t can be used to for timed events.
    t_start = time.time()
    t_seconds = 0                   # Number of seconds that have passed since this process started.

    # Configuration File and Node Information objects.
    config = None
    node_info = NodeInformation()

    # Module loading priority
    priority = 100  # 0 highest -> 100 lowest

    restart_count = 0  # How many times this module has been restarted

    """
    Installer Virtual Methods
    """

    def get_name(self):
        """
        :return: module name
        """
        # return self._name
        return type(self).__name__

    def get_version(self):
        """
        :return: module version
        """
        return self._version

    def add_installer_arguments(self, parser):
        pass

    def get_config(self):
        """
        :return: configuration
        """
        return self.config

    def disable_module(self):
        self._enabled = False

    def module_enabled(self):
        return self._enabled

    def validate_arguments(self, args):
        """
        Validate command line arguments and save values to our configuration object.
        :param args: An argparse object.
        :return: True if command line arguments are valid, otherwise False.
        """
        pass

    def validate_config(self, config):
        """
        Validate configuration file arguments and save values to our config object.
        :param config: A ConfigParser object.
        :return: True if configuration file values are valid, otherwise False.
        """
        pass

    def prepare_config(self, config):
        """
        Add the module configuration items that need to be saved to the configuration file.
        :param config: A ClientConfiguration object.
        :return: True if configuration file values were prepared correctly, otherwise False.
        """
        pass

    def set_config(self, config):
        """
        !!! Please Do not override this method
        """
        self.config = config
        if self.validate_config(config) is False:
            self.disable_module()

    def pre_install(self):
        """
        Called by the installer before the formal install process starts.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        pass

    def install_module(self):
        """
        Called by the installer during the formal install process.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        pass

    def post_install(self):
        """
        Called by the installer after the formal install process has completed.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        pass

    def uninstall_module(self):
        """
        Called by the installer during an uninstall process.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        pass

    """
    Service Daemon Virtual Methods
    """

    def service_startup(self):
        """
        Called by the service daemon during service start or reload.
        :return: True if successful, otherwise False.
        """
        pass

    def service_shutdown(self):
        """
        Called by the service daemon during service stop.
        :return: True if successful, otherwise False.
        """
        pass

    def process_task(self, task):
        """
        Process a QueueTask object and do something. Called by the process_handler method
        when there is a QueueTask object sent by the parent process.
        :param task:
        :return:
        """
        pass

    def process_loop(self):
        """
        This is called during after each idle timeout period has expired in process_handler.
        This method should do some work if needed and then return to the process_handler.
        Do not set a long term loop in this method. Doing so will break the parent processing.
        :return:
        """
        pass

    def timed_event(self, t_property, seconds):
        """
        Check to see if the number of seconds has passed based on the object property value.
        :param property: Property of the object that is keeping track of the last event time.
        :param seconds: Number of seconds that need to pass before the next event time.
        :return: True if event time is now, False if not.
        """
        # Get the property value
        t_property_val = getattr(self, t_property)

        # Check to see if we have reached the next event time.
        if self.t_seconds > t_property_val and self.t_seconds % seconds == 0.0:
            setattr(self, t_property, self.t_seconds)
            return True

        return False

    def process_handler(self, queue, mqueue, mlist):
        """
        !!! Please do not override this method, override the process_loop method !!!
        Called during the service loop.
        :param queue: Multiprocessing queue object.
        """
        _logger.debug('{0} processing thread started.'.format(self.get_name()))

        # Save parent's manager queue.
        self._mqueue = mqueue

        # Save list of all loaded module names.
        self._mlist = mlist

        while True:

            try:
                task = queue.get(timeout=self._queue_timeout)  # Wait while looking for a QueueTask object.
            except:
                self.t_seconds = int(time.time() - self.t_start)  # Set the number of seconds since process start.
                self.process_loop()  # Call the processing loop for module idle processing.
                continue

            try:
                # _logger.debug('{0}: received task id: {1}.'.format(self.get_name(), task.get_task_id()))
                if task.get_task_id() == TASK_STOP_PROCESSING:
                    _logger.debug('{0}: received stop signal, ending process handler.'.format(self.get_name()))
                    self.service_shutdown()
                    break

                # Process task.
                self.process_task(task)

            except:
                raise
                # _logger.debug('{0}: received bad task object, discarding.'.format(self.get_name()))

        _logger.debug('{0}: Module processing thread closed cleanly.'.format(self.get_name()))

    def send_parent_task(self, qtask):
        """
        Send a QueueTask object to the parent process.
        :param qtask: QueueTask object
        :return:
        """
        if self._mqueue:
            self._mqueue.put(qtask)
        else:
            _logger.error('{0}: Task submitted to parent, but queue not ready.'.format(self.get_name()))

    def __lt__(self, other):
        """Sort modules by priority"""
        return self.priority < other.priority


def __load_modules__(base_path=None, module_path='silentdune_client/modules'):
    """
    Search for modules to load.  Modules must reside under the modules directory and
    have a "module_list" dict defined in the __init__.py file. Each entry in the
    "module_list" must list a Class that subclasses BaseModule.
    """

    module_list = list()

    # Loop through the directories looking for modules to import.
    for root, dirs, files in os.walk(os.path.join(base_path, module_path), topdown=True):
        # Skip our directory.
        if root == '.':
            continue

        # Look only at __init__.py files.
        for name in files:
            if name == '__init__.py':

                # Remove base_path and convert to dotted path.
                mp = root.replace(base_path + '/', '').replace('./', '').replace('/', '.')

                # Attempt to import 'module_list' from __init__.py file.
                try:
                    ml = import_by_str(mp + '.module_list')

                # If we get an Exception check to see if the python module loaded but there was no
                # client module definition found, otherwise just reraise the last Exception for debugging.
                except ModuleLoadError:
                    # Looks like a clean import error. IE: __init__.py is not a real module.
                    continue
                except:
                    # Found a module to load, but it threw an Exception. Just pass the Exception up.
                    raise

                for mname, mdict in ml.items():
                    # _logger.debug('Found module definition "{0}" in path {1}'.format(mname, mp))
                    for key, name in mdict.items():

                        if key == 'module':
                            tpath = mp + '.' + name
                            try:
                                mod = import_by_str(tpath)
                                module_list.append(mod())
                                _logger.debug('Adding "{0}" module ({1}).'.format(mname, tpath))
                            except ImportError:
                                _logger.error('Adding "{0}" module failed. ({1}).'.format(mname, tpath))
                                pass

    return module_list
