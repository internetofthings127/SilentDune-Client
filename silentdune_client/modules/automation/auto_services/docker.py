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
import subprocess

from silentdune_client.modules.automation.auto_services.base_service import BaseService
from silentdune_client.utils.misc import which, is_service_running

_logger = logging.getLogger('sd-client')

DOCKERCOMMANDS = {
    'ps': 'docker ps -a --format="{{.ID}}|{{.Image}}|{{.CreatedAt}}|{{.RunningFor}}|{{.Status}}"',
    'inspect': 'docker inspect {0}',
}


class DockerService(BaseService):
    _service_name = '_service_docker'

    def _discover_iptables(self):
        """
        Look for running docker service. If found, check for containers that require firewall rules.
        :return:
        """

        rules = list()

        docker = which('docker')
        if not docker:
            _logger.debug("{0}: Failed to find 'docker' executable.".format(self._module))
            return rules

        if not is_service_running('docker'):
            _logger.debug("{0}: Docker service not running.".format(self._module))
            return rules

        p = subprocess.Popen([u'ntpq', u'-p', u'-n'], stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        result = p.wait()

        if stderrdata is None:
            data = stdoutdata.decode('utf-8')
            for line in data.split('\n'):
                items = line.split('|')

                #
                # service fields:
                #   node_id
                #   pid char(100)
                #   name char(250)
                #   type char(100) (system service, docker container, ...)
                #   running bool
                #   runningfor char(100)
                #   panic bool
                #   delete bool (remove service record on purge)
                #
                #
                #
