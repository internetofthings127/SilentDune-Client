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

from importlib import import_module

from silentdune_client.utils.exceptions import ModuleLoadError


def import_by_str(mod):
    """
    Import a dotted module path and return the attribute/class designated by the
    last name in the path. Raise ImportError if the import failed.
    """

    # If these throw Exceptions, just let them bubble to the parent.
    mpath, cname = mod.rsplit('.', 1)
    module = import_module(mpath)

    try:
        return getattr(module, cname)
    except AttributeError as e:
        msg = str(e)

        # If this is a "'module' object has no attribute 'module_list'" message raise an ModuleLoadError,
        # otherwise reraise the AttributeError Exception so we can get the cause and stacktrace of the
        # Exception.
        if "no attribute 'module_list'" in msg:
            raise ModuleLoadError('Not a loadable module')
        else:
            raise

