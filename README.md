About OSPD-IKESCAN
-------------------

This is a OSP server implementation to allow GVM to remotely control
a ike-scan scanner, see http://www.nta-monitor.com/tools-resources/security-tools/ike-scan

OSPD-IKESCAN tries to identify IPSEC VPN endpoints. It will attempt to
enumerate supported cipher suites, bruteforce valid groupnames and
fingerprint any endpoint identified.

Once running, you need to configure the Scanner for Greenbone Vulnerability
Manager, for example via the web interface Greenbone Security Assistant.
Then you can create scan tasks to use this scanner.

OSPD-IKESCAN is licensed under GNU General Public License Version 2 or
any later version.  Please see file COPYING for details.

All parts of OSPD-IKESCAN are Copyright (C) by Greenbone Networks GmbH
(see http://www.greenbone.net).


How to start OSPD-IKESCAN
--------------------------

There are no special usage aspects for this module
beyond the general usage guide.

Please follow the general usage guide for ospd-based scanners:

  https://github.com/greenbone/ospd/blob/master/doc/USAGE-ospd-scanner
