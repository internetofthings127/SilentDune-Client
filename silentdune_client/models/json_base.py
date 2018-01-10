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

import json


class JsonObject(object):
    """
    Base JSON for all data objects.  Allows for converting JSON data into the object models.
    """

    # _json_data = False

    def __init__(self, *args, **kwargs):
        """
        If parameter values in args, then the value is expected to be a dictionary from a json response
        from the server.

        If parameter values are in kwargs, then they are named parameters passed when the object is instantiated.
        """
        if args is not None and len(args) is not 0 and args[0] is not None:
            # self._json_data = True
            for key, value in args[0].items():
                self.__dict__[key] = value
                # print('{0} : {1}'.format(key, value))

        else:
            for key, value in kwargs.items():
                self.__dict__[key] = value
                # print('{0} : {1}'.format(key, value))

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, indent=3)

    def to_dict(self):
        data = dict()
        for key, value in self.__dict__.items():
            if not key.startswith("__") and value is not None:
                data[key] = value
        return data

    def dict_to_obj_array(self, cls, data):
        """
        # Convert dict to array of objects of type cls
        """
        if data is None:
            return None

        ol = list()
        for x in range(0, len(data)):
            ol.append(cls(data[x]))

        return ol
