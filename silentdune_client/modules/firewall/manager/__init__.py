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

import hashlib
import logging
import os
import pkg_resources
import subprocess
from subprocess import CalledProcessError
import sys

from silentdune_client import modules
from silentdune_client.builders import iptables as ipt
from silentdune_client.models.iptables_rules import IPMachineSubset, IPRulesFileWriter
from silentdune_client.modules.firewall.manager.slots import Slots
from silentdune_client.modules.firewall.manager.iptables_utils import create_iptables_tcp_ingress_egress_rule, \
    create_iptables_loopback, create_iptables_ingress_egress_forward_reject_rule, check_transport_value, \
    create_iptables_ingress_egress_reject_rule
from silentdune_client.modules.firewall.manager.utils import create_generic_dns_egress_rules, \
    create_generic_ntp_egress_rules
from silentdune_client.utils.misc import validate_network_address, is_service_running, which

# Import other module's TASK defines, set to None if module is not present.
# TODO:
try:
    from silentdune_client.modules.comm.sd_server import TASK_SEND_SERVER_ALERT
    from silentdune_client.modules.comm.sd_server import TASK_SEND_SERVER_ALERT_2  # noqa
except ImportError:
    TASK_SEND_SERVER_ALERT = None


_logger = logging.getLogger('sd-client')

""" Tell the firewall to reload all rules from disk """
TASK_FIREWALL_RELOAD_RULES = 100

""" Tell the firewall to allow all DNS queries """
TASK_FIREWALL_ALLOW_ALL_DNS_ACCESS = 110
TASK_FIREWALL_DISABLE_ALL_DNS_ACCESS = 111

""" Tell the firewall to allow all HTTP(S) queries """
TASK_FIREWALL_ALLOW_ALL_HTTP_ACCESS = 120
TASK_FIREWALL_DISABLE_ALL_HTTP_ACCESS = 121

""" Tell the firewall to allow all NTP queries """
TASK_FIREWALL_ALLOW_ALL_NTP_ACCESS = 140
TASK_FIREWALL_DISABLE_ALL_NTP_ACCESS = 141

TASK_FIREWALL_INSERT_RULES = 201
TASK_FIREWALL_DELETE_RULES = 202
TASK_FIREWALL_DELETE_SLOT = 203


# Define the available Module classes.
module_list = {
    'Silent Dune Firewall Manager': {
        'module': 'SilentDuneClientFirewallModule',
    },
}


class SilentDuneClientFirewallModule(modules.BaseModule):
    """ Silent Dune Server Module """

    priority = 0  # Highest loading priority.

    _rules = None  # List with IPTablesMachineSubset objects.
    _startup = True

    _disable_auto_ssh = False
    _sshd_running = False
    _sshd_rules = None

    _allowed_networks = None  # None == All

    def __init__(self):

        self._arg_name = 'firewall'
        self._config_section_name = 'firewall'

        # Enable multi-threading
        self.wants_processing_thread = True

        try:
            self._version = pkg_resources.get_distribution(__name__).version
        except:
            self._version = 'unknown'

    def install_module(self):
        """
        Virtual Override
        """
        return True

    def add_installer_arguments(self, parser):
        """
        Virtual Override
        Add our module's argparser arguments
        """

        # Create a argument group for our module
        group = parser.add_argument_group('firewall', 'Silent Dune Firewall')

        group.add_argument(_('--allowed-networks'), help=_('Restrict access to specified networks.'),  # noqa
                           default='', type=str, required=False)
        group.add_argument(_('--disable-auto-ssh'), help=_('Disable auto SSH rule creation.'),  # noqa
                           default=False, action='store_true')  # noqa

    def validate_arguments(self, args):
        """
        Virtual Override
        Validate command line arguments and save values to our configuration object.
        :param args: An argparse object.
        """

        self._allowed_networks = args.allowed_networks

        # if we have network addresses, check them.
        if self._allowed_networks:
            if not validate_network_address(self._allowed_networks):
                print('sdc-install: argument --allowed-networks value invalid.')
                return False

        if '--allowed-networks' not in sys.argv and '--iso-all-rules' in sys.argv:
            print('sdc-install: warning, --iso-all-rules parameter has no affect.')

        self._disable_auto_ssh = args.disable_auto_ssh

        return True

    def validate_config(self, config):
        """
        Virtual Override
        Validate configuration file arguments and save values to our config object.
        :param config: A ConfigParser object.
        """

        self._allowed_networks = config.get(self._config_section_name, 'allowed_networks')

        # if we have network addresses, check them.
        if self._allowed_networks:
            if not validate_network_address(self._allowed_networks):
                _logger.error('{0} invalid Allowed Networks value.'.format(self.get_name()))
                return False

        self._disable_auto_ssh = \
            True if config.get(self._config_section_name, 'disable_auto_ssh').lower() == 'yes' else False

        return True

    def prepare_config(self, config):
        """
        Virtual Override
        Return the configuration file structure. Any new configuration items should be added here.
        Note: The order should be reverse of the expected order in the configuration file.
        """

        config.set(self._config_section_name, 'allowed_networks',
                   self._allowed_networks if self._allowed_networks else '')
        config.set(self._config_section_name, 'disable_auto_ssh', 'yes' if self._disable_auto_ssh else 'no')

        config.set_comment(self._config_section_name, self._config_section_name,
                           _('; Silent Dune Firewall Configuration\n'))  # noqa
        config.set_comment(self._config_section_name, 'allowed_networks',
                           _('; Set allowed networks this system can connect to.\n' +  # noqa
                             '; List of networks in CIDR notation, delimited with spaces.\n' +  # noqa
                             '; Empty value allows access to all networks.'))  # noqa
        config.set_comment(self._config_section_name, 'disable_auto_ssh',
                           _('; Disable the auto SSH rule generation.\n'))  # noqa

        return True

    def service_startup(self):

        _logger.debug('{0} module startup called'.format(self.get_name()))

        p = subprocess.Popen(['modprobe', 'ip_conntrack'], stdin=subprocess.PIPE)
        p.communicate()
        result = p.wait()
        if result:
            _logger.error('{0}: kernel module loading of ip_conntrack reported an error.'.format(self.get_name()))

        p = subprocess.Popen(['modprobe', 'ip_conntrack_ftp'], stdin=subprocess.PIPE)
        p.communicate()
        result = p.wait()
        if result:
            _logger.error('{0}: kernel module loading of ip_conntrack_ftp reported an error.'.format(self.get_name()))

        self.restore_iptables()
        self.load_rule_bundles()

        return True

    def service_shutdown(self):

        _logger.debug('{0} thread shutdown called'.format(self.get_name()))
        self.save_iptables()

        # Flush rules and chains from iptables and ip6tables.
        for i in ['iptables', 'ip6tables']:
            try:
                subprocess.call([i, '--flush'])
                subprocess.call([i, '--delete-chain'])
            except CalledProcessError:
                pass

    def process_loop(self):
        # _logger.debug('{0} processing loop called'.format(self.get_name()))

        # Add SSH access rules.
        if self._startup:
            # Add loopback rules
            self.add_firewall_rule(self.get_loopback_rules())

            # Add sshd service rules
            if is_service_running('sshd'):
                self._sshd_rules = self.create_ssh_rules()
                self.add_firewall_rule(self._sshd_rules)
                self._sshd_running = True

            # Add rejection rules.
            self.add_firewall_rule(self.create_reject_rules())

            # Add network isolation rules
            if self._allowed_networks:
                self.add_firewall_rule(self.create_network_isolation_rules())

            self.write_rules_to_iptables_file()
            self.restore_iptables()

            self._startup = False

        # Check to see if sshd is running or not.
        if is_service_running('sshd'):
            if not self._sshd_running:
                self._sshd_rules = self.create_ssh_rules()
                self.add_firewall_rule(self._sshd_rules)
                self._sshd_running = True
                self.write_rules_to_iptables_file()
                self.restore_iptables()
        else:
            if self._sshd_running and self._sshd_rules:
                _logger.debug('{0}: removing sshd service rules.'.format(self.get_name()))
                self.del_firewall_rule(self._sshd_rules)
                self._sshd_running = False
                self.write_rules_to_iptables_file()
                self.restore_iptables()

    def process_task(self, task):

        if task:

            t_id = task.get_task_id()

            if t_id == TASK_FIREWALL_RELOAD_RULES:
                _logger.debug('{0}: {1}: reloading firewall rules.'.format(
                    self.get_name(), 'TASK_FIREWALL_RELOAD_RULES'))
                self.restore_iptables()

            if t_id == TASK_FIREWALL_INSERT_RULES:
                _logger.debug('{0}: {1}: received rules from module {2}.'.format(
                    self.get_name(), 'TASK_FIREWALL_INSERT_RULES', task.get_sender()))
                self.add_firewall_rule(task.get_data())
                self.write_rules_to_iptables_file()
                self.restore_iptables()

            if t_id == TASK_FIREWALL_DELETE_RULES:
                _logger.debug('{0}: {1}: received rules from module {2}.'.format(
                    self.get_name(), 'TASK_FIREWALL_DELETE_RULES', task.get_sender()))
                self.del_firewall_rule(task.get_data())
                self.write_rules_to_iptables_file()
                self.restore_iptables()

            if t_id == TASK_FIREWALL_DELETE_SLOT:
                _logger.debug('{0}: {1}: received rules from module {2}.'.format(
                    self.get_name(), 'TASK_FIREWALL_DELETE_SLOT', task.get_sender()))
                self.del_firewall_slot(task.get_data())
                self.write_rules_to_iptables_file()
                self.restore_iptables()

            if t_id == TASK_FIREWALL_ALLOW_ALL_DNS_ACCESS:
                _logger.debug('{0}: {1}: request for ALL DNS access from module {2}.'.format(
                              self.get_name(), 'TASK_FIREWALL_ALLOW_ALL_DNS_ACCESS', task.get_sender()))
                rules = create_generic_dns_egress_rules()
                self.add_firewall_rule(rules)
                self.write_rules_to_iptables_file()
                self.restore_iptables()

            if t_id == TASK_FIREWALL_DISABLE_ALL_DNS_ACCESS:
                _logger.debug('{0}: {1}: request to remove ALL DNS access from module {2}.'.format(
                              self.get_name(), 'TASK_FIREWALL_ALLOW_ALL_DNS_ACCESS', task.get_sender()))
                rules = create_generic_dns_egress_rules()
                self.del_firewall_rule(rules)
                self.write_rules_to_iptables_file()
                self.restore_iptables()

            if t_id == TASK_FIREWALL_ALLOW_ALL_NTP_ACCESS:
                _logger.debug('{0}: {1}: request for all NTP access from module {2}.'.format(
                              self.get_name(), 'TASK_FIREWALL_ALLOW_ALL_NTP_ACCESS', task.get_sender()))
                rules = create_generic_ntp_egress_rules()
                self.add_firewall_rule(rules)
                self.write_rules_to_iptables_file()
                self.restore_iptables()

            if t_id == TASK_FIREWALL_DISABLE_ALL_NTP_ACCESS:
                _logger.debug('{0}: {1}: request to remove all NTP access from module {2}.'.format(
                              self.get_name(), 'TASK_FIREWALL_ALLOW_ALL_NTP_ACCESS', task.get_sender()))
                rules = create_generic_ntp_egress_rules()
                self.del_firewall_rule(rules)
                self.write_rules_to_iptables_file()
                self.restore_iptables()

    def load_rule_bundles(self):
        """
        Load the user defined json bundle files, each file is a IPMachineSubset json object.
        :return:
        """
        ol = list()
        for file in os.listdir(self.node_info.config_root):
            if '.bundle' in file:
                try:
                    with open(os.path.join(self.node_info.config_root, file)) as handle:
                        mss = IPMachineSubset(handle)

                        if 2000 <= mss.slot <= 8999:  # only load user defined slot range numbers.
                            ol.append(mss)
                except:
                    _logger.error('{0}: Bundle file is corrupt, unable to load {1}.'.format(self.get_name(), file))
                    continue

        if len(ol) > 0:
            ol.sort(key=lambda x: x.slot)

        self._rules = ol

    def restore_iptables(self):
        """
        Load the iptables save file and load it into the kernel.
        This is only called on startup.
        """
        # Load rule files into kernel
        for v in [u'ipv4', u'ipv6']:

            file = os.path.join(self.node_info.config_root, u'{0}.rules'.format(v))
            if os.path.exists(file):
                try:
                    with open(file) as handle:
                        data = handle.read()

                    if v == u'ipv4':
                        p = subprocess.Popen([self.node_info.iptables_restore, '-c'], stdin=subprocess.PIPE)
                    else:
                        p = subprocess.Popen([self.node_info.ip6tables_restore, '-c'], stdin=subprocess.PIPE)
                    p.communicate(data.encode('utf-8'))
                    result = p.wait()

                    if result:
                        _logger.error('{0}: iptables-restore reported an error loading data.'.format(self.get_name()))

                except ValueError:
                    _logger.error('{0}: Invalid arguments passed to iptables-restore.'.format(self.get_name()))
                except OSError:
                    _logger.error('{0}: Loading IPv4 rules into kernel failed.'.format(self.get_name()))
            else:
                _logger.error('{0}: Rules file ({1}) not found.'.format(self.get_name(), file))

                # TODO: The SD Server module should be notified if there is any error loading a rule file.

    def save_iptables(self):
        """
        Dump the iptables information from the kernel and save it to the restore file.
        This is only called on shutdown.
        """

        # Load rule files into kernel
        for v in [u'ipv4', u'ipv6']:

            file = os.path.join(self.node_info.config_root, u'{0}.rules'.format(v))
            try:
                if v == u'ipv4':
                    p = subprocess.Popen([self.node_info.iptables_save, '-c'], stdout=subprocess.PIPE)
                else:
                    p = subprocess.Popen([self.node_info.ip6tables_save, '-c'], stdout=subprocess.PIPE)

                data = p.communicate()[0]
                result = p.wait()

                if result:
                    _logger.error('{0}: iptables-save reported an error.'.format(self.get_name()))
                else:
                    with open(file, 'w') as handle:
                        handle.write(str(data))

            except ValueError:
                _logger.error('{0}: Invalid arguments passed to iptables-save.'.format(self.get_name()))
            except OSError:
                _logger.error('{0}: Saving IPv4 rules from kernel failed.'.format(self.get_name()))

            if TASK_SEND_SERVER_ALERT:
                pass
                # TODO: The SD Server module should be notified if there is any error saving a rule file.

        # Restore the selinux context if needed
        self.node_info.restorecon(self.node_info.config_root)

    def add_firewall_rule(self, obj):
        """
        Add a IPTablesMachineSubset to the list of rules
        :param obj: IPTablesMachineSubset object or array of IPTablesMachineSubset objects.
        :return: True if rules were successfully added, otherwise False.
        """
        try:
            nmss = hashlib.sha1(obj.to_json().encode('utf-8')).hexdigest()

            # Loop through the current rules and see if the rule already exists.
            for mss in self._rules:
                if hashlib.sha1(mss.to_json().encode('utf-8')).hexdigest() == nmss:
                    # _logger.debug('{0}: Rule has already been added to rule list.'.format(self.get_name()))
                    return True

            self._rules.append(obj)
            self._rules.sort(key=lambda x: x.slot)

            return True

        except AttributeError:

            try:
                # See if we have a list of IPTablesMachineSubset objects. If so, recursively add them.
                if len(obj) > 0:
                    for o in obj:
                        if o:
                            self.add_firewall_rule(o)
                    # for mss in self._rules:
                    #     _logger.debug('{0} Adding rule ({1}): {2}'.format(self.get_name(), mss.slot, mss.name))
                    _logger.debug('{0}: Added {1} rules.'.format(self.get_name(), len(obj)))
                    return True
            except TypeError:
                _logger.error('{0} Invalid IPMachineSubset passed, unable to add rules.'.format(self.get_name()))

        return False

    def del_firewall_rule(self, obj):
        """
        Remove a IPTablesMachineSubset from the list of rules
        :param obj:
        :return:
        """

        try:
            nmss = hashlib.sha1(obj.to_json().encode('utf-8')).hexdigest()

            # Loop through the current rules and see if the rule already exists.
            for mss in self._rules:
                if hashlib.sha1(mss.to_json().encode('utf-8')).hexdigest() == nmss:
                    self._rules.remove(mss)
                    self._rules.sort(key=lambda x: x.slot)
                    return True

        except AttributeError:

            try:
                # See if we have a list of IPTablesMachineSubset objects. If so, recursively remove them.
                if len(obj) > 0:
                    for o in obj:
                        self.del_firewall_rule(o)
                    _logger.debug('{0}: Removed {1} IPTablesMachineSubset object rules.'.format(
                        self.get_name(), len(obj)))
                    return True
            except TypeError:
                _logger.error('{0}: Invalid IPMachineSubset passed, unable to remove.'.format(self.get_name()))

        return False

    def del_firewall_slot(self, slot):
        """
        Remove all rules that match the slot id parameter
        :param slot: Slot ID
        :return: True if successful, otherwise False.
        """

        rules = list()

        try:
            # Loop through the current rules and see if rules of the chain already exists.
            for mss in self._rules:
                jsonobj = mss.to_dict()
                if jsonobj[u'slot'] == slot:
                    rules.append(mss)

            # delete rules of the chain
            self.del_firewall_rule(rules)

            return True

        except AttributeError:

            _logger.error('{0}: Unable to delete slot ({1}) rules.'.format(self.get_name(), slot))

        return False

    def write_rules_to_iptables_file(self):
        """
        Output to file in iptables format our list of IPTablesMachineSubset objects.
        :return:
        """
        for v in [u'ipv4', u'ipv6']:
            file = os.path.join(self.node_info.config_root, u'{0}.rules'.format(v))

            _logger.debug('{0}: Writting {1} rules to -> {2}'.format(self.get_name(), v, file))

            writer = IPRulesFileWriter(self._rules)
            writer.write_to_file(file, v)

            if not self.validate_rule_files(v, file):
                return False

        return True

    def validate_rule_files(self, protocol, file):
        """
        Validate multiple iptables rule save files.
        :param files: List of path+filenames to run iptables-restore --test on.
        :return:
        """

        if not self.node_info.root_user:
            _logger.warning('{0}: Unable to validate rules, not running as privileged user.'.format(self.get_name()))
            return True

        # Loop through files and test the validity of the file.
        if not os.path.exists(file):
            _logger.error('{0} {1} save file ({2}) does not exist.'.format(self.get_name(), protocol, file))
            return False

        with open(file) as handle:
            data = handle.read()

        if protocol == u'ipv4':
            p = subprocess.Popen([self.node_info.iptables_restore, '--test'], stdin=subprocess.PIPE)
        else:
            p = subprocess.Popen([self.node_info.ip6tables_restore, '--test'], stdin=subprocess.PIPE)

        p.communicate(data.encode('utf-8'))
        result = p.wait()

        if result:
            _logger.error('{0}: {1} validation failed on iptables save file: {2}'.format(
                self.get_name(), protocol, file))

            if TASK_SEND_SERVER_ALERT:
                # TODO: Notify server of error.
                pass

        return True

    def generate_emergency_rules(self):
        """
        Generate temp admin access only rules and set firewall
        :return:
        """
        pass

    def get_loopback_rules(self):
        """
        Create Loopback rules for internal access
        :return: Loopback rules
        """

        rules = list()

        _logger.debug('{0}: adding loopback interface rules.'.format(self.get_name()))
        rules.append(create_iptables_loopback(Slots.loopback, transport=ipt.TRANSPORT_IPV4))
        rules.append(create_iptables_loopback(Slots.loopback, transport=ipt.TRANSPORT_IPV6))

        return rules

    def create_ssh_rules(self):
        """
        Create SSH rules for administrative access.
        :return: SSH Rules.
        """

        rules = list()

        # See if we should not add any ssh rules.
        if self._disable_auto_ssh:
            return rules

        conf = u'/etc/ssh/sshd_config'
        port = 22

        # Check the sshd config and see if it is using a non-standard port.
        if not os.path.exists(conf):
            _logger.warning('{0}: sshd_config not found, using standard SSH port.'.format(self.get_name()))

        try:
            with open(conf) as handle:
                content = handle.readlines()

            if content:
                for line in content:
                    if line.lower().strip().startswith('port '):
                        port = int(line.split()[1])
                        break
        except:
            pass

        _logger.debug('{0}: adding sshd service rules.'.format(self.get_name()))
        rules.append(create_iptables_tcp_ingress_egress_rule(None, port, Slots.admin, transport=ipt.TRANSPORT_IPV4))
        rules.append(create_iptables_tcp_ingress_egress_rule(None, port, Slots.admin, transport=ipt.TRANSPORT_IPV6))

        return rules

    def create_reject_rules(self):
        """
        Create auto rejection rules for Input, Forward and Output
        :return:
        """

        rules = list()

        _logger.debug('{0}: adding reject rules.'.format(self.get_name()))
        rules.append(create_iptables_ingress_egress_forward_reject_rule(Slots.reject, transport=ipt.TRANSPORT_IPV4))
        rules.append(create_iptables_ingress_egress_forward_reject_rule(Slots.reject, transport=ipt.TRANSPORT_IPV6))

        return rules

    def create_network_isolation_rules(self):

        rules = list()
        transport_list = list()

        _logger.debug('{0}: adding network isolation rules.'.format(self.get_name()))

        for cidr in self._allowed_networks.split(' '):

            cidr = cidr.encode('utf-8')

            if not validate_network_address(cidr):
                _logger.error('{0} unable to validate network cidr value "{1}"'.format(self.get_name(), cidr))
                continue

            # Get IP transport version from address.
            ipaddr, bits = cidr.split('/')
            transport = check_transport_value(ipaddr, ipt.TRANSPORT_AUTO)

            # Save the transports we use so we can add the reject rules later.
            if transport not in transport_list:
                transport_list.append(transport)

            rules.append(ipt.get_machine_subset(
                "network iso",
                Slots.network_iso,
                [
                    ipt.get_chain(
                        u'filter',
                        [
                            ipt.get_ring(
                                u'input',
                                transport,
                                [
                                    ipt.get_rule(source_address=cidr, jump=ipt.get_jump(target=u'RETURN'))
                                ]
                            ),
                            ipt.get_ring(
                                u'output',
                                transport,
                                [
                                    ipt.get_rule(dest_address=cidr, jump=ipt.get_jump(target=u'RETURN'))
                                ]
                            ),
                        ]
                    )
                ]
            ))

        # Create network isolation rejection rules.
        for transport in transport_list:
            rules.append(create_iptables_ingress_egress_reject_rule(Slots.network_iso, transport, 'iso reject'))

        return rules
