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
import sys

_logger = logging.getLogger('sd-client')


class ConsoleBase(object):
    """
    Output messages to the console.
    """

    silent = False

    # http://stackoverflow.com/questions/11245381/formatting-console-output

    def cwrite(self, message, debug_msg=None):
        """
        Write a message to stdout or to debug logger with no linefeed.
        """

        if _logger.getEffectiveLevel() == logging.DEBUG:
            if debug_msg is None:
                _logger.debug(message)
            else:
                _logger.debug(debug_msg)
        elif not self.silent:
            # TODO: If silent, add the module name (prefix?) to the message
            sys.stdout.write(message)
            sys.stdout.flush()

    def cwriteline(self, message, debug_msg=None):
        """
        Write a message to stdout or to debug logger with linefeed.
        """

        if _logger.getEffectiveLevel() == logging.DEBUG:
            if debug_msg is None:
                _logger.debug(message)
            else:
                _logger.debug(debug_msg)
        elif not self.silent:
            # TODO: If silent, add the module name (prefix?) to the message
            print(message)
            sys.stdout.flush()
