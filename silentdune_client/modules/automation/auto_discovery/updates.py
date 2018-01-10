#
# Authors: Ma He <mahe.itsec@gmail.com>
#          Robert Abram <robert.abram@entpack.com>

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

from datetime import datetime
import fnmatch
import glob
import logging
import os
import platform
import shlex
import socket
import subprocess
import time

try:
    from urllib import parse
except ImportError:
    # < 3.0
    import urlparse as parse

import ConfigParser
from silentdune_client.modules import QueueTask
from silentdune_client.modules.firewall.manager import SilentDuneClientFirewallModule, \
    TASK_FIREWALL_INSERT_RULES
from silentdune_client.builders import iptables as ipt
from silentdune_client.modules.automation.auto_discovery.base_discovery_service import BaseDiscoveryService
from silentdune_client.modules.firewall.manager.iptables_utils import create_iptables_egress_ingress_rule, \
    create_iptables_egress_rule_dest, create_iptables_ingress_rule_source
from silentdune_client.modules.firewall.manager.slots import Slots
from silentdune_client.utils.misc import which

_logger = logging.getLogger('sd-client')


class SystemUpdatesDiscovery(BaseDiscoveryService):
    """
    Auto discover SystemUpdates like apt-get and yum.
    """

    _rebuild_rules_interval = 5  # Rebuild the updates cache rules every 5 days.

    _slot = Slots.updates
    _config_section_name = 'auto_discovery'
    _config_property_name = '_disable_auto_updates'
    _dist = ''
    _dist_version = ''
    _machine = ''
    _disable_auto_updates_ftp = None
    _disable_auto_updates_rsync = None

    _rebuild_rules = True  # Rebuild the rules
    _rebuild_cache = False  # Should we rebuild the package manager cache?
    _cache_last_rebuilt = None  # Time stamp last time cache was rebuilt.

    _hostnames = list()  # Previously added hostnames

    _repo_manager = None
    _repo_cache_base = ''
    _repo_config_base = ''
    _repo_service_base = ''  # openSUSE/SLES systems

    _saved_rules = None

    def __init__(self, config):
        super(SystemUpdatesDiscovery, self).__init__(config)
        self._disable_auto_updates_ftp = True if self.config.get(
            self._config_section_name, 'disable_auto_updates_ftp').lower() == 'yes' else False

    def _discover_iptables(self):
        """
        Virtual Override
        :return: Firewall Rules
        """

        rules = list()

        # Find the system package manager executable and setup our environment info
        if not self._repo_manager and not self.discover_pkg_manager():
            _logger.error('{0}: unable to continue setting up rules for updates.'.format(self.get_name()))
            return None

        # Test to see if DNS lookup is available right now.  If not, just return and wait until DNS is working.
        if not self.resolve_hostname('example.org', 80):
            return None

        # Every 5 days rebuild the rules.
        if self._cache_last_rebuilt:
            days = int((datetime.now() - self._cache_last_rebuilt).days)
            if days >= self._rebuild_rules_interval:
                self._rebuild_rules = True

        rules.append(self.iptables_updates())

        return rules

    def discover_pkg_manager(self):
        """
        Find the system package manager executable
        :return: True if found, otherwise False
        """

        self._dist = platform.dist()[0].lower()
        self._dist_version = platform.dist()[1]
        self._dist_version = self._dist_version.split('.')[0]
        self._machine = platform.machine()

        if self._dist in 'ubuntu debian':
            self._repo_manager = which('apt-get')
            # Nothing else to do.

        elif self._dist in 'centos redhat fedora':

            self._repo_config_base = '/etc/yum.repos.d/*.repo'

            self._repo_manager = which('dnf')
            self._repo_cache_base = '/var/cache/dnf'

            if not self._repo_manager:
                self._repo_manager = which('yum')
                self._repo_cache_base = '/var/cache/yum/{0}/{1}'.format(self._machine, self._dist_version)

        elif self._dist in 'suse':
            self._repo_manager = which('zypper')
            self._repo_config_base = '/etc/zypp/repos.d/*.repo'
            self._repo_service_base = '/etc/zypp/services.d/*.service'
            # No metalink cache until suse implements metalinks in zypper

        else:
            _logger.error('{0}: unsupported distribution ({1})'.format(self.get_name(), self._dist))
            return False

        if not self._repo_manager:
            _logger.error('{0}: unable to find package manager executable for {1}'.format(self.get_name(), self._dist))
            return False

        return True

    def iptables_updates(self):

        rules = list()

        if self._dist in 'ubuntu debian':
            rules.append(self.iptables_updates_apt())

        elif self._dist in 'centos redhat fedora':
            rules.append(self.add_repository_rules())

        elif self._dist in 'suse':
            rules.append(self.add_repository_rules())

        return rules

    def iptables_updates_apt(self):

        rules = list()

        if not os.path.exists('/etc/apt/sources.list'):
            _logger.error('{0}: /etc/apt/sources.list not found.'.format(self.get_name()))
            return None

        # Get all nameserver ip address values
        with open('/etc/apt/sources.list') as handle:

            for line in handle:

                if line.startswith('deb '):
                    url = line.split()[1]
                    if url:
                        rules.append(self.add_rule_by_url(url))

        return rules

    def add_repository_rules(self):
        """
        Add repository rules for rpm based systems.
        """

        # If it is not time to rebuild the package manager cache, just return the rules we have.
        if not self._rebuild_rules:
            return self._saved_rules

        self._rebuild_cache = False

        # reset hostnames list
        self._hostnames = list()

        rules = list()
        base_urls = list()
        mirror_urls = list()

        _logger.debug('{0}: adding rules for {1} repositories'.format(self.get_name(), self._dist))

        # Loop through all the repo files and gather url information
        repofiles = glob.glob(self._repo_config_base)

        # Add in any zypper service files.
        if self._dist in 'suse':
            repofiles += glob.glob(self._repo_service_base)

        for repofile in repofiles:

            config = ConfigParser.ConfigParser()
            if config.read(repofile):

                sections = config.sections()

                # Loop through sections looking for enabled repositories.
                for section in sections:

                    if config.has_option(section, 'enabled'):
                        enabled = config.getint(section, 'enabled')
                    else:
                        enabled = 1

                    if not enabled:
                        continue

                    _logger.debug('{0}: adding urls for section: {1}'.format(self.get_name(), section))

                    url = None

                    if config.has_option(section, 'metalink'):
                        url = config.get(section, 'metalink')
                        self._rebuild_cache = True
                        if url:
                            mirror_urls.append([section, url])

                    elif config.has_option(section, 'mirrorlist'):
                        url = config.get(section, 'mirrorlist')
                        self._rebuild_cache = True
                        if url:
                            mirror_urls.append([section, url])

                    elif config.has_option(section, 'baseurl'):
                        url = config.get(section, 'baseurl')
                        if url:
                            base_urls.append([section, url])

                    # Handle zypper service files.
                    elif config.has_option(section, 'url'):
                        url = config.get(section, 'url')
                        if url:
                            base_urls.append([section, url])

                    if not url:
                        _logger.debug('{0}: could not find repo section ({1}) url?'.format(self.get_name(), section))

        # Loop through all the urls and add rules for them.
        for section, url in base_urls:

            # TODO: Add support for mirrorbrain style mirrorlists.

            rules.append(self.add_rule_by_url(url))

        # If we don't need to rebuild the package manager cache, just return the rules we have.
        if not self._rebuild_cache:
            return rules

        for section, url in mirror_urls:
            rules.append(self.add_rule_by_url(url))

        # Rebuild the package manager cache
        # Open up all port 80 and port 443 connections so cache rebuild succeeds.
        all_access = list()
        all_access.append(create_iptables_egress_ingress_rule(
            '', 80, 'tcp', self._slot, transport=ipt.TRANSPORT_IPV4))
        all_access.append(create_iptables_egress_ingress_rule(
            '', 80, 'tcp', self._slot, transport=ipt.TRANSPORT_IPV6))
        all_access.append(create_iptables_egress_ingress_rule(
            '', 443, 'tcp', self._slot, transport=ipt.TRANSPORT_IPV4))
        all_access.append(create_iptables_egress_ingress_rule(
            '', 443, 'tcp', self._slot, transport=ipt.TRANSPORT_IPV6))

        # our parent will take care of clearing these rules once we return the real rules.
        self.add_url_rule_to_firewall(all_access)

        time.sleep(2)  # Give the firewall manager time to add the rules.

        if not self.rebuild_package_manager_cache():
            return rules

        # Check to see if we know where the package manage cache data is.
        if not self._repo_cache_base:
            return rules

        # loop through the mirror list and parse the mirrorlist or metalink file.
        for section, url in mirror_urls:

            file, file_type = self.get_cache_file(section)

            if file:
                if file_type == 'mirrorlist':
                    urls = self.get_mirrorlist_urls_from_file(file, section)
                else:
                    urls = self.get_metalink_urls_from_file(file, section)

                if urls:
                    for url in urls:
                        if url:
                            rules.append(self.add_rule_by_url(url))

        self._cache_last_rebuilt = datetime.now()
        self._saved_rules = rules

        return rules

    def get_cache_file(self, section):
        """
        Auto detect the mirror list path, file and type.
        :param section: config section name
        :return: file and file type
        """

        if 'yum' in self._repo_manager:
            cachepath = '{0}/{1}'.format(self._repo_cache_base, section)

        elif 'dnf' in self._repo_manager:

            # Get all the files and directories in the cache base dir
            files = os.listdir(self._repo_cache_base)

            # Filter out only the directories we are looking for
            files = fnmatch.filter(files, '{0}-????????????????'.format(section))

            # Now figure out which path is the newest one.
            cachepath = '{0}/{1}/'.format(self._repo_cache_base, max(files, key=os.path.getmtime))

        else:
            return None, ''

        if not os.path.isdir(cachepath):
            _logger.error('{0}: calculated cache path is invalid ({1})'.format(self.get_name(), cachepath))
            return None, ''

        # detect url cache file and type
        if os.path.isfile('{0}/mirrorlist.txt'.format(cachepath)):
            return '{0}/mirrorlist.txt'.format(cachepath), 'mirrorlist'

        if os.path.isfile('{0}/mirrorlist'.format(cachepath)):
            return '{0}/mirrorlist'.format(cachepath), 'mirrorlist'

        if os.path.isfile('{0}/metalink.xml'.format(cachepath)):
            return '{0}/metalink.xml'.format(cachepath), 'metalink'

        _logger.error('{0}: cache file is not found ({1})'.format(self.get_name(), cachepath))

        return None, ''

    def rebuild_package_manager_cache(self):
        """
        Have the package manager clean and rebuild it's cache information
        :return: True if successful, otherwise False
        """

        if self._dist in 'suse':
            cmd_clean = '{0} clean'.format(self._repo_manager)
            cmd_make = '{0} refresh'.format(self._repo_manager)

        elif self._dist in 'centos redhat fedora':
            cmd_clean = '{0} clean metadata'.format(self._repo_manager)
            cmd_make = '{0} makecache fast'.format(self._repo_manager)

        else:
            _logger.error('{0}: unsupported package manager, unable to rebuild cache.')
            return False

        _logger.debug('{0}: rebuilding {1} package manager cache data'.format(self.get_name(), self._dist))

        # Clean package manager cache
        p = subprocess.Popen(shlex.split(cmd_clean), stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        p.wait()

        if stderrdata:
            _logger.error('{0}: cleaning package manager cache failed.'.format(self.get_name()))
            return False

        # Rebuild the package manager cache
        p = subprocess.Popen(shlex.split(cmd_make), stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        p.wait()

        if stderrdata:
            _logger.error('{0}: rebuilding package manager cache failed.'.format(self.get_name()))
            return False

        return True

    def add_url_rule_to_firewall(self, rules):
        """
        Add rules allowing access immediately to the firewall.
        :param rules: rules list
        """
        if not rules:
            return

        # Notify the firewall module to reload the rules.
        task = QueueTask(TASK_FIREWALL_INSERT_RULES,
                         src_module=self._parent.get_name(),
                         dest_module=SilentDuneClientFirewallModule().get_name(),
                         data=rules)
        self._parent.send_parent_task(task)

        time.sleep(2)  # Give the firewall manager time to add the rule to the kernel

    def resolve_hostname(self, hostname, port):
        """
        Return a single or multiple IP addresses from the hostname parameter
        :param hostname: hostname string, IE: www.example.org
        :param port:
        :return: list of IP addresses
        """

        ipaddrs = list()

        if hostname:
            if port:
                if 1 < port <= 65536:
                    try:
                        ais = socket.getaddrinfo(hostname, port, 0, 0, socket.IPPROTO_TCP)
                    except:
                        _logger.debug('{0}: error resolving host: {1}:{2}'.format(self.get_name(), hostname, port))
                        return None

                    for result in ais:
                        ipaddr = result[-1][0]
                        ipaddrs.append(ipaddr)

        return ipaddrs

    def add_rule_by_url(self, url):
        """
        :param url: Complete url string
        :return: urlparse URI
        """

        rules = list()

        if not url:
            _logger.debug('{0}: empty url given, unable to add rule'.format(self.get_name()))
            return None

        try:
            uri = parse.urlparse(url)
        except:
            _logger.error('{0}: error parsing url ({1})'.format(self.get_name(), url))
            return None

        if not uri.scheme or not uri.hostname or uri.scheme not in ['http', 'https', 'ftp', 'rsync']:
            return None

        # If this is an FTP url...
        if uri.scheme == 'ftp':
            return self.add_ftp_rule_by_url(uri)

        port = uri.port

        if not port:

            if uri.scheme == 'http':
                port = 80
            elif uri.scheme == 'https':
                port = 443
            elif uri.scheme == 'rsync':
                port = 873

        key = uri.hostname + ':' + str(port)

        # Avoid duplicate urls.
        if key not in self._hostnames:
            self._hostnames.append(key)

            ipaddrs = self.resolve_hostname(uri.hostname, port)

            if ipaddrs:
                for ipaddr in ipaddrs:

                    # _logger.debug('{0}: adding ip: {1} from hostname: {2}'.format(
                    #     self.get_name(), uri.scheme + '://' + ipaddr, uri.hostname))

                    rules.append(create_iptables_egress_ingress_rule(
                        ipaddr, port, 'tcp', self._slot, transport=ipt.TRANSPORT_AUTO))

                    _logger.debug('{0}: host: {1}  ip: {2}:{3}'.format(self.get_name(), uri.hostname, ipaddr, port))

            return rules

        return None

    def add_ftp_rule_by_url(self, uri):
        """
        Add rules to allow FTP access based on uri value
        :param uri: urlparse uri value
        :return: rules
        """

        # Check to make sure we can add ftp rules.
        if self._disable_auto_updates_ftp:
            return None

        rules = list()

        ipaddrs = self.resolve_hostname(uri.hostname, 21)

        if ipaddrs:
            for ipaddr in ipaddrs:

                _logger.debug('{0}: adding ip: {1} from hostname: {2}'.format(
                    self.get_name(), uri.scheme + '://' + ipaddr, uri.hostname))

                # FTP control
                rules.append(create_iptables_egress_ingress_rule(ipaddr, 21, 'tcp', self._slot,
                                                                 transport=ipt.TRANSPORT_AUTO))
                # FTP data transfer
                rules.append(create_iptables_egress_rule_dest(ipaddr, 20, 'tcp', self._slot, 'ESTABLISHED',
                                                              transport=ipt.TRANSPORT_AUTO))
                rules.append(
                    create_iptables_ingress_rule_source(ipaddr, 20, 'tcp', self._slot, 'ESTABLISHED,RELATED',
                                                        transport=ipt.TRANSPORT_AUTO))
                rules.append(
                    create_iptables_egress_rule_dest(ipaddr, None, 'tcp', self._slot, 'ESTABLISHED,RELATED',
                                                     transport=ipt.TRANSPORT_AUTO))
                rules.append(
                    create_iptables_ingress_rule_source(ipaddr, None, 'tcp', self._slot, 'ESTABLISHED',
                                                        transport=ipt.TRANSPORT_AUTO))

        return rules

    def get_mirrorlist_urls_from_file(self, file, section):

        urls = list()

        if not file or not os.path.isfile(file):
            _logger.debug('{0}: unable to locate mirrorlist file ({1})'.format(self.get_name(), file))
            return urls

        with open(file) as handle:
            lines = handle.read().split('\n')

            if lines:
                for line in lines:
                    if line.strip():
                        urls.append(line.strip())

        _logger.debug('{0}: retrieving mirrorlist urls for "{1}" succeeded'.format(self.get_name(), section))
        return urls

    def get_metalink_urls_from_file(self, file, section):

        urls = list()

        if not file or not os.path.isfile(file):
            _logger.debug('{0}: unable to locate metalink file ({1})'.format(self.get_name(), file))
            return urls

        with open(file) as handle:
            lines = handle.read().split('\n')

            if lines:
                for line in lines:
                    if line.find('<url protocol=') != -1:
                        url = line.split(' >')[1].split('</url>')[0].strip()
                        if url:
                            urls.append(url)
                    if line.find('xmlns="') != -1:
                        url = line.split('xmlns="')[1].split('"')[0].strip()
                        if url:
                            urls.append(url)
                    if line.find('xmlns:mm0="') != -1:
                        url = line.split('xmlns:mm0="')[1].split('"')[0].strip()
                        if url:
                            urls.append(url)

            else:
                _logger.debug('{0}: no data read from metalink file ({1})'.format(self.get_name(), file))
                return None

        _logger.debug('{0}: retrieving metalink urls for "{1}" succeeded'.format(self.get_name(), section))

        return urls

    # def grab_mirror_list_urls(self, mirrorlist, section):
    #     """
    #     Attempt to download repository mirrorlist data using curl and return the urls.
    #     :param mirrorlist:
    #     :return: url list
    #     """
    #     urls = list()
    #
    #     if mirrorlist:
    #
    #         mirrorlist = mirrorlist.replace('$releasever', self._dist_version)
    #         mirrorlist = mirrorlist.replace('$basearch', self._machine)
    #         mirrorlist = mirrorlist.replace('$infra', 'stock')
    #
    #         c = pycurl.Curl()
    #         transport = c.IPRESOLVE_V4
    #
    #         # Force curl IPv4 DNS lookup, if that fails try IPv6 DNS lookup.
    #         while True:
    #             try:
    #                 storage = StringIO()
    #                 c = pycurl.Curl()
    #                 c.setopt(c.URL, mirrorlist.encode('utf-8'))
    #                 c.setopt(c.IPRESOLVE, transport)
    #                 c.setopt(c.WRITEFUNCTION, storage.write)
    #                 c.perform()
    #                 c.close()
    #                 content = storage.getvalue()
    #                 urllist = content.split('\n')
    #                 for url in urllist:
    #                     if url.strip():
    #                         urls.append(url.strip())
    #                 break
    #             except pycurl.error as e:
    #
    #                 if transport == c.IPRESOLVE_V4:
    #                     transport = c.IPRESOLVE_V6
    #                     continue
    #
    #                 _logger.debug('{0}: {1}: retrieving mirror list failed ({2})'.format(self.get_name(), section, e))
    #                 return None
    #
    #     _logger.debug('{0}: retrieving mirror list for section "{1}" succeeded'.format(self.get_name(), section))
    #     return urls

        # def grab_metalink_urls(self, metalink, section):
    #     """
    #     Attempt to download repository metalink data using curl and return the urls.
    #     :param metalink: metalink url
    #     :return: url list
    #     """
    #
    #     urls = list()
    #     content = None
    #
    #     if metalink:
    #         metalink = metalink.replace('$releasever', self._dist_version)
    #         metalink = metalink.replace('$basearch', self._machine)
    #
    #         c = pycurl.Curl()
    #         transport = c.IPRESOLVE_V4
    #
    #         # Force curl IPv4 DNS lookup, if that fails try IPv6 DNS lookup.
    #         while True:
    #             try:
    #                 storage = StringIO()
    #                 c = pycurl.Curl()
    #                 c.setopt(c.URL, metalink.encode('utf-8'))
    #                 c.setopt(c.IPRESOLVE, transport)
    #                 c.setopt(c.WRITEFUNCTION, storage.write)
    #                 c.perform()
    #                 c.close()
    #                 content = storage.getvalue()
    #                 break
    #             except pycurl.error as e:
    #
    #                 if transport == c.IPRESOLVE_V4:
    #                     transport = c.IPRESOLVE_V6
    #                     continue
    #
    #                 _logger.debug('{0}: retrieving metalink list failed ({1})'.format(self.get_name(), e))
    #                 return None
    #
    #         if content:
    #             lines = content.split('\n')
    #             for line in lines:
    #                 if line.find('<url protocol=') != -1:
    #                     url = line.split(' >')[1].split('</url>')[0]
    #                     if url:
    #                         urls.append(url.strip())
    #                 if line.find('xmlns="') != -1:
    #                     url = line.split('xmlns="')[1].split('"')[0]
    #                     if url:
    #                         urls.append(url.strip())
    #                 if line.find('xmlns:mm0="') != -1:
    #                     url = line.split('xmlns:mm0="')[1].split('"')[0]
    #                     if url:
    #                         urls.append(url.strip())
    #
    #     _logger.debug('{0}: retrieving metalink list for section "{1}" succeeded'.format(self.get_name(), section))
    #     return urls
