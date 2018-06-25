# -*- coding: utf-8 -*-
# Description:
# Core of the OSP ikescan Server
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

import subprocess
import logging

from ospd.ospd import OSPDaemon
from ospd.misc import main as daemon_main
from ospd_ikescan import __version__

logger = logging.getLogger(__name__)

OSPD_IKESCAN_DESC = """
This scanner runs the tool 'ike-scan' on the local host where the scanner is installed.

ike-scan tries to identify IPSEC VPN endpoints. It will attempt to enumerate supported cipher suites,
bruteforce valid groupnames and fingerprint any endpoint identified.
"""

OSPD_IKESCAN_PARAMS = \
    {'source_port':
     {'type': 'integer',
      'name': 'Source port number',
      'default': 500,
      'mandatory': 0,
      'description': 'The source port number used by ike-scan.',},

     'dest_port':
     {'type': 'integer',
      'name': 'Destination port number',
      'default': 500,
      'mandatory': 0,
      'description': 'The destionation port number used by ike-scan.',},

     'transport':
     {'type': 'selection',
      'name': 'Transport to use',
      'default': 'udp|udp|tcp',
      'mandatory': 0,
      'description': 'Whether to use TCP or UDP to run ike-scan.',},

     'tcp_mode':
     {'type': 'selection',
      'name': 'Type of IKE over TCP',
      'default': '1|1|2',
      'mandatory': 0,
      'description': '1 = RAW IKE over TCP as used by Checkpoint (default), '
                     '2 = Encapsulated IKE over TCP as used by Cisco.',},

     'use_nat_t':
     {'type': 'boolean',
      'name': 'Use NAT-Traversal',
      'default': '0',
      'mandatory': 0,
      'description': 'Whether to use  RFC 3947 NAT-Traversal encapsulation.',},

     'nat_t_source_port':
     {'type': 'integer',
      'name': 'Source port number for NAT-Traversal',
      'default': 4500,
      'mandatory': 0,
      'description': 'The source port number for NAT-Traversal used by ike-scan.',},

     'nat_t_dest_port':
     {'type': 'integer',
      'name': 'Destination port number',
      'default': 4500,
      'mandatory': 0,
      'description': 'The destionation port number for NAT-Traversal used by ike-scan.',},

     'aggressive_mode':
     {'type': 'boolean',
      'name': 'Enable Aggressive Mode',
      'default': 1,
      'mandatory': 0,
      'description': 'Whether to use Aggressive Mode to run ike-scan.',},

     'main_mode':
     {'type': 'boolean',
      'name': 'Enable Main Mode',
      'default': 0,
      'mandatory': 0,
      'description': 'Whether to use Main Mode to run ike-scan.',},

     'fingerprint_aggressive_mode':
     {'type': 'boolean',
      'name': 'Enable fingerprint using Aggressive Mode',
      'default': 0,
      'mandatory': 0,
      'description': 'Whether to fingerprint using Aggressive Mode.',},

     'fingerprint_main_mode':
     {'type': 'boolean',
      'name': 'Enable fingerprint using Main Mode',
      'default': 0,
      'mandatory': 0,
      'description': 'Whether to fingerprint using Main Mode.',},

     'group_names':
     {'type': 'string',
      'name': 'Group names',
      'default': 'vpn',
      'mandatory': 0,
      'description': 'A comma sperated list of group names to use.',},

     'encryption_algorithms':
     {'type': 'string',
      'name': 'Encryption algorithms',
      'default': '1,2,3,4,5,6,7/128,7/196,7/256,8',
      'mandatory': 0,
      'description': 'A comma seperated list of encryption algorithms to use. Possible values are: '
                     '1 -> DES , '
                     '2 -> IDEA , '
                     '3 -> Blowfish , '
                     '4 -> RC5 , '
                     '5 -> 3DES , '
                     '6 -> CAST , '
                     '7/128 -> AES-128 , '
                     '7/196 -> AES-196 , '
                     '7/256 -> AES-256 , '
                     '8 -> Camellia',},

     'hash_algorithms':
     {'type': 'string',
      'name': 'Hash algorithms',
      'default': '1,2,3,4,5,6',
      'mandatory': 0,
      'description': 'A comma seperated list of hash algorithms to use. Possible values are: '
                     '1 -> MD5 , '
                     '2 -> SHA1 , '
                     '3 -> Tiger , '
                     '4 -> SHA-256 , '
                     '5 -> SHA-384 , '
                     '6 -> SHA-512',},

     'auth_methods':
     {'type': 'string',
      'name': 'Authentication methods',
      'default': '1,2,3,4,5,6,7,8,64221,65001',
      'mandatory': 0,
      'description': 'A comma seperated list of authentication methods to use. Possible values are: '
                     '1 -> PSK , '
                     '2 -> DSS-Signature , '
                     '3 -> RSA-Signature , '
                     '4 -> RSA-Encryption , '
                     '5 -> Revised-RSA-Encryption , '
                     '6 -> ElGamel-Encryption , '
                     '7 -> Revised-ElGamel-Encryption , '
                     '8 -> ECDSA-Signature , '
                     '64221 -> Hybrid , '
                     '65001 -> XAUTH',},

     'dh_groups':
     {'type': 'string',
      'name': 'Diffie-Hellmann groups',
      'default': '1,2,3,4,5',
      'mandatory': 0,
      'description': 'A comma seperated list of encryption algorithms to use. Possible values are: '
                     '1 -> MODP-768 , '
                     '2 -> MODP-1024 , '
                     '3 -> EC2N-155 , '
                     '4 -> EC2N-185 , '
                     '5 -> MODP-1536',},
      # technically we should do 1-20 <http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide#Diffie-Hellman_Group_Values> but that's a bitch

     'max_retry':
     {'type': 'integer',
      'name': 'Maximum retry',
      'default': '3',
      'mandatory': 0,
      'description': 'The total number of attempts per host.',},

     'max_timeout':
     {'type': 'integer',
      'name': 'Maximum timeout',
      'default': '500',
      'mandatory': 0,
      'description': 'The timeout for the first packet sent to each host.',},}


def get_ikescan_version():
    """ Check if ike-scan is executable and get the version """
    try:
        output = subprocess.check_output(['ike-scan', '--version'],
                                         stderr=subprocess.STDOUT)
    except OSError:
        return None
    for line in str(output, 'utf-8').split('\n'):
        if line.startswith("ike-scan "):
            return line.split()[1]
    return None


class OSPDikescan(OSPDaemon):

    """ Class for ospd-ikescan daemon. """

    def __init__(self, certfile, keyfile, cafile):
        """ Initializes the ospd-ikescan daemon's internal data. """
        super(OSPDikescan, self).__init__(certfile=certfile, keyfile=keyfile,
                                          cafile=cafile)
        self.server_version = __version__
        self.scanner_info['name'] = 'ike-scan'
        self.scanner_info['version'] = get_ikescan_version()
        self.scanner_info['description'] = OSPD_IKESCAN_DESC
        for name, param in OSPD_IKESCAN_PARAMS.items():
            self.add_scanner_param(name, param)

    def check(self):
        """ Checks that ike-scan is found and is executable. """
        if not self.scanner_info['version']:
            logger.error("Check for ike-scan failed.")
            return False
        return True

    def exec_scan(self, scan_id, target):
        """ Starts the ike-scan scanner for scan_id scan. """

        options = self.get_scan_options(scan_id)
        source_port = options.get('source_port')
        dest_port = options.get('dest_port')
        transport = options.get('transport')
        tcp_mode = options.get('tcp_mode')
        use_nat_t = options.get('use_nat_t')
        nat_t_source_port = options.get('nat_t_source_port')
        nat_t_dest_port = options.get('nat_t_dest_port')
        aggressive_mode = options.get('aggressive_mode')
        main_mode = options.get('main_mode')
        fingerprint_aggressive_mode = options.get('fingerprint_aggressive_mode')
        fingerprint_main_mode = options.get('fingerprint_main_mode')
        group_names = options.get('group_names')
        encryption_algorithms = options.get('encryption_algorithms')
        hash_algorithms = options.get('hash_algorithms')
        auth_methods = options.get('auth_methods')
        dh_groups = options.get('dh_groups')
        max_retry = options.get('max_retry')
        max_timeout = options.get('max_timeout')
        main_command = ''

        if use_nat_t == 1:
            if nat_t_source_port:
                main_command = '%s--sport=%s ' % (main_command, nat_t_source_port)

            if nat_t_dest_port:
                main_command = '%s--dport=%s ' % (main_command, nat_t_dest_port)
        else:
            if source_port:
                main_command = '%s--sport=%s ' % (main_command, source_port)

            if dest_port:
                main_command = '%s--dport=%s ' % (main_command, dest_port)

        if max_retry:
            main_command = '%s--retry=%s ' % (main_command, max_retry)

        if max_timeout:
            main_command = '%s--timeout=%s ' % (main_command, max_timeout)

        if transport == 1:
            main_command = '%s--tcp=%s ' % (main_command, tcp_mode)
            if use_nat_t == 1:
                report_port = '%s/tcp' % nat_t_dest_port
                host_report = '%s' % nat_t_dest_port
            else:
                report_port = '%s/tcp' % dest_port
                host_report = '%s' % dest_port
        else:
            if use_nat_t == 1:
                report_port = '%s/udp' % nat_t_dest_port
                host_report = '%s' % nat_t_dest_port
            else:
                report_port = '%s/udp' % dest_port
                host_report = '%s' % dest_port

        # Split user input in lists and save amout of iterations
        group_names_list = group_names.split(",")
        gnl_iterations = len(group_names_list)
        encryption_algorithms_list = encryption_algorithms.split(",")
        eal_iterations = len(encryption_algorithms_list)
        hash_algorithms_list = hash_algorithms.split(",")
        hal_iterations = len(hash_algorithms_list)
        auth_methods_list = auth_methods.split(",")
        aml_iterations = len(auth_methods_list)
        dh_groups_list = dh_groups.split(",")
        dhl_iterations = len(dh_groups_list)
        iterations = 1  # starting with 1 because of the first check for an onlie endpoint
        index = 0

        # calculate overall number of iterations for scan progress
        if aggressive_mode == 1:
            iterations += gnl_iterations * eal_iterations * hal_iterations * aml_iterations * dhl_iterations

        if main_mode == 1:
            iterations += eal_iterations * hal_iterations * aml_iterations * dhl_iterations

        if fingerprint_aggressive_mode == 1:
            iterations += gnl_iterations * eal_iterations * hal_iterations * aml_iterations * dhl_iterations

        if fingerprint_main_mode == 1:
            iterations += eal_iterations * hal_iterations * aml_iterations * dhl_iterations

        # Check if this is an IPSEC VPN endpoint
        try:
            if use_nat_t == 1:
                result = subprocess.check_output(['ike-scan', '--nat-t', main_command, target])
                used_command = 'ike-scan --nat-t %s%s' % (main_command, target)
            else:
                result = subprocess.check_output(['ike-scan', main_command, target])
                used_command = 'ike-scan %s%s' % (main_command, target)
            index += 1
            progress = index * 100 / iterations
            self.set_scan_progress(scan_id, int(progress))
        except subprocess.CalledProcessError as errmsg:
            logger.debug(str(errmsg))
            self.add_scan_error(
                scan_id, host=target,
                value='A problem occurred trying to execute "ike-scan": %s' % str(errmsg))
            return 2

        result = str(result, 'utf-8')
        if target in result or '127.0.0.1' in result:
            report = 'An IPSEC VPN endpoint was detected on this host using:\n\n%s\n\nike-scan returned:\n\n%s' % (used_command, result)
            self.add_scan_alarm(scan_id, host=target, name='IPSEC VPN endpoint detected',
                                qod=95, value=report, port=report_port)
            self.add_scan_host_detail(scan_id, host=target, name="ports",
                                      value=host_report)
            if 'tcp' in transport:
                self.add_scan_host_detail(scan_id, host=target, name="tcp_ports",
                                          value=host_report)
            else:
                self.add_scan_host_detail(scan_id, host=target, name="udp_ports",
                                          value=host_report)
        else:
            report = 'No IPSEC VPN endpoint was detected on this host using:\n\n%s\n\nike-scan returned:\n\n%s' % (used_command, result)
            self.add_scan_alarm(scan_id, host=target, name='No IPSEC VPN endpoint detected',
                                qod=95, value=report, port=report_port)

        if aggressive_mode == 1:
            for group_name in group_names_list:
                for encryption_algorithm in encryption_algorithms_list:
                    for hash_algorithm in hash_algorithms_list:
                        for auth_method in auth_methods_list:
                            for dh_group in dh_groups_list:

                                try:
                                    trans = '--trans=%s,%s,%s,%s' % (encryption_algorithm, hash_algorithm, auth_method, dh_group)
                                    if use_nat_t == 1:
                                        result = subprocess.check_output(['ike-scan', '--aggressive',
                                                                          '--nat-t', trans, '-n', group_name, main_command, target])
                                        used_command = 'ike-scan --aggressive --nat-t %s -n %s %s%s' % (trans, group_name, main_command, target)
                                    else:
                                        result = subprocess.check_output(['ike-scan', '--aggressive',
                                                                          trans, '-n', group_name, main_command, target])
                                        used_command = 'ike-scan --aggressive %s -n %s %s%s' % (trans, group_name, main_command, target)
                                    result = str(result, 'utf-8')
                                    if 'Aggressive Mode Handshake returned' in result:
                                        report = ('Aggressive Mode Handshaking succeeded using:\n\n%s\n\n'
                                                  '\n\nike-scan returned:\n\n%s'
                                                  '\n\nSince the VPN endpoint answers to requests using IKE Aggressive Mode Handshaking,'
                                                  'an attacker could potentially carry out a bruteforce attack against this host.'
                                                  % (used_command, result))
                                        self.add_scan_alarm(scan_id, host=target, name='IKE Aggressive Mode Handshake returned',
                                                            qod=95, value=report, port=report_port, severity='5.0')
                                    index += 1
                                    progress = index * 100 / iterations
                                    self.set_scan_progress(scan_id, int(progress))

                                except subprocess.CalledProcessError as errmsg:
                                    logger.debug(str(errmsg))
                                    self.add_scan_error(scan_id, host=target,
                                                        value='A problem occurred trying to execute "ike-scan": %s' % str(errmsg))
                                    return 2

        if main_mode == 1:
            for encryption_algorithm in encryption_algorithms_list:
                for hash_algorithm in hash_algorithms_list:
                    for auth_method in auth_methods_list:
                        for dh_group in dh_groups_list:

                            try:
                                trans = '--trans=%s,%s,%s,%s' % (encryption_algorithm, hash_algorithm, auth_method, dh_group)
                                if use_nat_t == 1:
                                    result = subprocess.check_output(['ike-scan', '--nat-t', trans, main_command, target])
                                    used_command = 'ike-scan --nat-t %s %s%s' % (trans, main_command, target)
                                else:
                                    result = subprocess.check_output(['ike-scan', trans, main_command, target])
                                    used_command = 'ike-scan %s %s%s' % (trans, main_command, target)
                                result = str(result, 'utf-8')
                                if 'Main Mode Handshake returned' in result:
                                    report = 'Main Mode Handshaking succeeded using:\n\n%s\n\nike-scan returned:%s' % (used_command, result)
                                    self.add_scan_alarm(scan_id, host=target, name='IKE Main Mode Handshake returned',
                                                        qod=95, value=report, port=report_port)
                                index += 1
                                progress = index * 100 / iterations
                                self.set_scan_progress(scan_id, int(progress))

                            except subprocess.CalledProcessError as errmsg:
                                logger.debug(str(errmsg))
                                self.add_scan_error(scan_id, host=target,
                                                    value='A problem occurred trying to execute "ike-scan": %s' % str(errmsg))
                                return 2

        if fingerprint_aggressive_mode == 1:
            for group_name in group_names_list:
                for encryption_algorithm in encryption_algorithms_list:
                    for hash_algorithm in hash_algorithms_list:
                        for auth_method in auth_methods_list:
                            for dh_group in dh_groups_list:

                                try:
                                    trans = '--trans=%s,%s,%s,%s' % (encryption_algorithm, hash_algorithm, auth_method, dh_group)
                                    if use_nat_t == 1:
                                        result = subprocess.check_output(['ike-scan', '--aggressive', '--showbackoff',
                                                                          '--nat-t', trans, '-n', group_name, main_command, target])
                                        used_command = 'ike-scan --aggressive --showbackoff --nat-t %s -n %s %s%s' % (trans, group_name, main_command, target)
                                    else:
                                        result = subprocess.check_output(['ike-scan', '--aggressive', '--showbackoff',
                                                                          trans, '-n', group_name, main_command, target])
                                        used_command = 'ike-scan --aggressive --showbackoff %s -n %s %s%s' % (trans, group_name, main_command, target)
                                    result = str(result, 'utf-8')
                                    if 'Aggressive Mode Handshake returned' in result:
                                        report = ('Aggressive Mode Handshaking and Fingerprinting succeeded using:\n\n%s\n\n'
                                                  '\n\nike-scan returned:\n\n%s'
                                                  '\n\nSince the VPN endpoint answers to requests using IKE Aggressive Mode Handshaking,'
                                                  'an attacker could potentially carry out a bruteforce attack against this host.'
                                                  % (used_command, result))
                                        self.add_scan_alarm(scan_id, host=target, name='IKE Aggressive Mode Handshake and Fingerprint returned',
                                                            qod=95, value=report, port=report_port, severity='5.0')
                                    index += 1
                                    progress = index * 100 / iterations
                                    self.set_scan_progress(scan_id, int(progress))

                                except subprocess.CalledProcessError as errmsg:
                                    logger.debug(str(errmsg))
                                    self.add_scan_error(scan_id, host=target,
                                                        value='A problem occurred trying to execute "ike-scan": %s' % str(errmsg))
                                    return 2

        if fingerprint_main_mode == 1:
            for encryption_algorithm in encryption_algorithms_list:
                for hash_algorithm in hash_algorithms_list:
                    for auth_method in auth_methods_list:
                        for dh_group in dh_groups_list:

                            try:
                                trans = '--trans=%s,%s,%s,%s' % (encryption_algorithm, hash_algorithm, auth_method, dh_group)
                                if use_nat_t == 1:
                                    result = subprocess.check_output(['ike-scan', '--showbackoff', '--nat-t', trans, main_command, target])
                                    used_command = 'ike-scan --showbackoff --nat-t %s %s%s' % (trans, main_command, target)
                                else:
                                    result = subprocess.check_output(['ike-scan', '--showbackoff', trans, main_command, target])
                                    used_command = 'ike-scan --showbackoff %s %s%s' % (trans, main_command, target)
                                result = str(result, 'utf-8')
                                if 'Main Mode Handshake returned' in result:
                                    report = ('Aggressive Mode Handshaking and Fingerprinting succeeded using:\n\n%s\n\n'
                                              '\n\nike-scan returned:\n\n%s'
                                              % (used_command, result))
                                    self.add_scan_alarm(scan_id, host=target, name='IKE Main Mode Handshake and Fingerprint returned',
                                                        qod=95, value=report, port=report_port)
                                index += 1
                                progress = index * 100 / iterations
                                self.set_scan_progress(scan_id, int(progress))

                            except subprocess.CalledProcessError as errmsg:
                                logger.debug(str(errmsg))
                                self.add_scan_error(scan_id, host=target,
                                                    value='A problem occurred trying to execute "ike-scan": %s' % str(errmsg))
                                return 2
        return 0


def main():
    """ OSP ikescan main function. """
    daemon_main('OSPD - ike-scan wrapper', OSPDikescan)
