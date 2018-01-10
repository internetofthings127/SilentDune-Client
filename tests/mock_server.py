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

from unittest import TestCase

try:
    from unittest import mock  # <- Python 3.x
except ImportError:
    import mock

from silentdune_client.modules.comm.sd_server.connection import SilentDuneConnection

# https://blog.fugue.co/2016-02-11-python-mocking-101.html
# http://stackoverflow.com/questions/15753390/python-mock-requests-and-the-response


def mock_server_requests_get(*args, **kwargs):
    """
    Add Server URLs and response data here for all GET requests.
    """

    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.cookies = {'csrftoken': 'BhJD6Y5WyGF0gMv6LJpREWcS0tOPUELV'}
            self.status_code = status_code

        def json(self):
            return self.json_data

    # Login attempt
    if args[0] == 'http://127.0.0.1:80/accounts/login/':
        return MockResponse({"status": "OK", "next": "/dashboard/"}, 200)

    return MockResponse({}, 404)


def mock_server_requests_post(*args, **kwargs):
    """
    Add Server URLs and response data here for all POST requests.
    """
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.cookies = {
                'csrftoken': 'BhJD6Y5WyGF0gMv6LJpREWcS0tOPUELV',
                'token': "gAAAAABXdDoHCXJJKaspX4gG1HYHn6MH0PFzgx_EAgooZoaqzkMbVlOwz_65NInIp2-6gKQ9WNEXW6KKF4R3yXM9DhPyKpGLaC2wkIQgKVWNiooqgw0bFQRlkQgLTOpapq7P04JyycVu9XlZuhN8VDkB6l5MjE-L9wBoNMgdnmtCB_82yC8WfesrzDyMSqJDaHhkXH6DvxNqkiqik_qYvXaN36WEWwep9D6Z3MakYY7DCUbAsVROkFxE7f7KdM6wQEp76DURJ2chozPD0KAftz4Gh8Opjv2beHRU-CRppABvVRCU6PS_Px0=",  # noqa
            }
            self.status_code = status_code

        def json(self):
            return self.json_data

    # Get encrypted oauth2 token
    if args[0] == 'http://127.0.0.1:80/accounts/login/':
        return MockResponse({"status": "OK", "next": "/dashboard/"}, 200)

    # Post iptables log event
    if args[0] == 'http://127.0.0.1:80/api/alerts/iptables/':
        return MockResponse({"id": 55}, 201)


class BaseServerPasswordConnection(TestCase):
    """
    Base class that other unit tests can inherit to automatically get a mock server connection.
    """

    sdc = None

    def setUp(self):

        self.make_connection()

    @mock.patch('silentdune_client.modules.comm.sd_server.connection.requests.get', autospec=True,
                side_effect=mock_server_requests_get)
    @mock.patch('silentdune_client.modules.comm.sd_server.connection.requests.post', autospec=True,
                side_effect=mock_server_requests_post)
    def make_connection(self, mock_get, mock_post):

        self.sdc = SilentDuneConnection('127.0.0.1', True, 80)
        self.sdc.connect_with_password('abcdabcd', '12341234')


