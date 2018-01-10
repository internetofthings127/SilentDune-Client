==================
Silent Dune Client
==================


A Open Source Multi-Threaded and Modular Linux Firewall Manager Service.

Silent Dune is a complete replacement for firewall services like FirewallD and UFW.

Silent Dune is here to elevate and extend system security to new levels.


Description
===========

The Primary Goal of this project is to make creating and managing **egress firewall
rules** as easy as possible for system administrators and to also log rule
violations and send those back to administrators as alerts that something bad
may be happening on their systems.

The Silent Dune Client is a new and powerful linux firewall management
service that extends firewall management in exciting new ways. The SDC
is modular and multi-threaded for great flexibility and performance.

Uses for SDC also include help with making systems HIPPA or PCI compliant
when setting egress rules are required for compliance.

Configuration File
------------------

/etc/silentdune/sdc.conf

Executables
-----------

**sdc-install**
  The installer disables any running firewall services, runs the installer and
  configuration code from each module. The final configuration is stored in
  /etc/silentdune/sdc.conf.

**sdc-firewall**
  This is the firewall service, it must be run as root. It can be run in the
  foreground (SystemD style) or in the background (SysInit style). Init service
  scripts and configuration files are in the project init directory.


Silent Dune Modules
===================

Firewall Manager Module
-----------------------

The FM module is the core of the SDC. This module communicates with the other
modules to add, remove and query firewall rules. This module also saves running
rules when shutdown and restores them on startup.


Logging Module
--------------

The LM is used to set firewall logging rules and to monitor the system log
for triggered rule events. The LM  provides a subscription service for
other modules to subscribe to receive the system log events.

Goal:
  *The purpose of the LM is to promote setting egress firewall rules.
  If all egress network traffic is constrained by rules, then any network
  activity that does not match the egress rules is potentially malicious and
  should be blocked.  The LM module can then capture that activity and depending
  on which other modules are used can provide alerts to administrators.*


Auto Discovery Module
---------------------

The AD module looks at the local system configuration to **create
egress rules** and sometimes ingress rules for external services required by
the system. The AD module will also over time recheck all items, looking for
changes and update the firewall rules accordingly.

This helps administrators by automating rule building for important external
services.

Goal:
  *Auto discover external services required for a system to be completely
  functional and set egress firewall rules to allow access to those services.
  Keep those rules up to date over time.*

Note:
  *The AD module will also set ingress and egress rules for SSH. Any of
  the discovery items can be disabled by administrators. Administrators using
  the SDS module (Silent Dune Server module) may want to disable SSH in AD
  and create fine grain SSH rules in the Silent Dune Server.*

  *The AD module also auto creates egress rejection rules for the OUTPUT and
  FORWARD chains.*

Discovery items include:

* DNS
* NTP
* System Updates (apt and yum, including mirrors)
* DHCP


Silent Dune Server Module
-------------------------

The SDS module provides a connection with a Silent Dune Server to allow central
management of a large number systems.

When used in conjunction with the **Auto Discovery** and **Logging** modules,
creating and managing egress firewall rules can be greatly simplified for
administrators.  See: [Silent Dune GitHub project](https://github.com/EntPack/SilentDune)


Modules In Development
======================

Remote Configuration (IOT) Module
---------------------------------

The RC module will allow a remote firewall rules to be downloaded and verified by
the SDC and applied to the system.  The RC module, when used in conjunction with
the Auto Discovery module, allows many systems locked down with network egress
rules to be remotely managed by a single configuration file.

Goal:
  *The RC module is meant to be used for bolt-on security for IOT (Internet of Things)
  devices. Using the RC module allows a system to be very secure but still communicate
  with a cloud API.  This also allows IOT systems to keep in sync as the cloud API
  infrastructure changes over time.*


Future Modules
==============

**If you are interested in working on any of these modules, please contact me.**
<https://github.com/robabram>

DBUS Module
-----------

Using DBUS inter-process communications to allow other process to create firewall
rules, specifically egress rules.

Goal:
  *One application of this I would like to see eventually is a email or web browser
  plugin that communicates with the SDC to allow egress traffic to high quality web sites.
  So if malicious code executes in an email attachment or the web browser and tries
  to communicate to an external Command and Control server, it would be blocked from
  doing so.*

  See BBC pure javascript ransomware article: http://www.bbc.com/news/technology-36575687

Docker Container Module
-----------------------

After talking with the Docker people at PyCon 2016, having a module that could
centrally manage and monitor the firewall settings on Docker containers would be
an exciting module for administrators to have.



LICENSE
=======

This project is licensed under the GPLv3 license. https://www.gnu.org/licenses/gpl-3.0.en.html



