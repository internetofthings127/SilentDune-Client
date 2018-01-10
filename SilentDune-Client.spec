####################################################
#
# Spec file for package SilentDune
#
# Copyright (c) 2016-2017 EntPack
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
####################################################

####################################################
# Global Vars
####################################################

%if ! %{defined _rundir}
%define _rundir %{_localstatedir}/run
%endif

# Define which version of python we will be using
%define use_python3 0

%if 0%{force_python2} == 1
%define pythonlib %{python2_sitelib}
%else
%if (0%{?fedora} >= 14 || 0%{?rhel} > 7)
%global with_python3 1
%if (0%{?fedora} >= 23 || 0%{?rhel} > 8)
%global use_python3 1
%define pythonlib %{python3_sitelib}
%else
%define pythonlib %{python2_sitelib}
%endif
%endif
%endif


# If using python2 define macros
%if 0%{?use_python3} == 0
%global py2_build %{__python} setup.py build
%global py2_install %{__python} setup.py install --root %{buildroot}
%define pythonlib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")
%endif

# Check if OS is using SystemD
%global use_systemd 0
%if (0%{?fedora} >= 14 || 0%{?rhel} >= 7 || 0%{?suse_version} >= 1210)
%global use_systemd 1
%endif

# Only build selinux package for redhat variants or fedora
%if (0%{?fedora} || 0%{?rhel})
# SELinux defines from: https://fedoraproject.org/wiki/SELinux_Policy_Modules_Packaging_Draft
%global selinux_types %(%{__awk} '/^#[[:space:]]*SELINUXTYPE=/,/^[^#]/ { if ($3 == "-") printf "%s ", $2 }' /etc/selinux/config 2>/dev/null)
%global selinux_variants %([ -z "%{selinux_types}" ] && echo mls targeted || echo %{selinux_types})
%{!?_selinux_policy_version: %global _selinux_policy_version %(sed -e 's,.*selinux-policy-\\([^/]*\\)/.*,\\1,' /usr/share/selinux/devel/policyhelp 2>/dev/null)}
%endif

####################################################
# Package Info
####################################################
%define name silentdune
%define version 0.1
%define unmangled_version 0.1
%define release 1

Name: %{name}
Version: %{version}
Release: %{release}
Summary: Silent Dune Modular Firewall Service

License: GPLv3
Url: https://www.entpack.com
Source0: %{name}-%{unmangled_version}.tar.gz

BuildArch: noarch

BuildRequires:  iptables python-setuptools

%if 0%{?suse_version}
BuildRequires:  python-devel systemd-rpm-macros procps sed
%else
BuildRequires: redhat-rpm-config
%if 0%{?use_python3}
BuildRequires:  python3-devel
%else
BuildRequires:  python2-devel
%endif
%endif

%if 0%{?use_systemd}
BuildRequires: systemd
%{?systemd_requires}
%else
%if 0%{?suse_version}
PreReq: %insserv_prereq %fillup_prereq
Requires(pre): python-enum34 python-dateutil python-dnspython python-requests
%else
Requires(post): chkconfig
Requires(postun): initscripts
Requires(preun): chkconfig
Requires(preun): initscripts
Requires: epel-release
%endif
%endif

Requires: iptables python-setuptools python-dateutil python-requests python-enum34

Conflicts: iptables-services firewalld SuSEfirewall2

%description
An Open Source Multi-Threaded and Modular Linux Firewall Manager Service
dedicated to setting Egress firewall rules and simplifying firewall
management.

#################
# Prep Step
#
%prep
%setup -n %{name}-%{unmangled_version}

%if (0%{?fedora} || 0%{?rhel})
mkdir SELinux
%if 0%{?rhel} == 6
cp -p silentdune_client/selinux/silentdune.fc.rh6dist.in SELinux/silentdune.fc
cp -p silentdune_client/selinux/silentdune.if.rh6dist.in SELinux/silentdune.if
cp -p silentdune_client/selinux/silentdune.te.rh6dist.in SELinux/silentdune.te
%else
cp -p silentdune_client/selinux/silentdune.fc.rh7dist.in SELinux/silentdune.fc
cp -p silentdune_client/selinux/silentdune.if.rh7dist.in SELinux/silentdune.if
cp -p silentdune_client/selinux/silentdune.te.rh7dist.in SELinux/silentdune.te
%endif
%endif

#################
# Build Step
#
%build
%if 0%{?use_python3}
%py3_build
%else
%py2_build
%endif

# Build SELinux policy
%if (0%{?fedora} || 0%{?rhel})
cd SELinux
for selinuxvariant in %{selinux_variants}
do
  make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile
  mv silentdune.pp silentdune.pp.${selinuxvariant}
  make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile clean
done
cd -
%endif

#################
# Install Step
#
%install
%if 0%{?use_python3}
%py3_install
%else
%py2_install
%endif
#python setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

# Move executables from bin to sbin
mv %{buildroot}/%{_bindir} %{buildroot}/sbin

install -d %{buildroot}%{_sysconfdir}/logrotate.d
install -p -m 644 %{buildroot}%{pythonlib}/silentdune_client/init/silentdune.logrotate.in \
   %{buildroot}%{_sysconfdir}/logrotate.d/silentdune

install -d %{buildroot}%{_rundir}/silentdune

# Handle service and config setup
install -d -m 750 %{buildroot}%{_sysconfdir}/silentdune

%if 0%{?use_systemd}
install -d %{buildroot}%{_unitdir}
install -p -m 444 %{buildroot}%{pythonlib}/silentdune_client/init/sdc-firewall.systemd.in %{buildroot}%{_unitdir}/sdc-firewall.service
install -p -m 640 %{buildroot}%{pythonlib}/silentdune_client/init/sdc.conf.systemd.in %{buildroot}%{_sysconfdir}/silentdune/sdc.conf
%else
install -d %{buildroot}%{_initddir}
install -p -m 755 %{buildroot}%{pythonlib}/silentdune_client/init/sdc-firewall.sysv.in %{buildroot}%{_initddir}/sdc-firewall
install -p -m 640 %{buildroot}%{pythonlib}/silentdune_client/init/sdc.conf.sysv.in %{buildroot}%{_sysconfdir}/silentdune/sdc.conf
%endif

# SELinux
%if (0%{?fedora} || 0%{?rhel})
for selinuxvariant in %{selinux_variants}
do
  install -d %{buildroot}%{_datadir}/selinux/${selinuxvariant}
  install -p -m 644 SELinux/silentdune.pp.${selinuxvariant} \
    %{buildroot}%{_datadir}/selinux/${selinuxvariant}/silentdune.pp
done
%endif

#################
# Clean Step
#
%clean
rm -rf $RPM_BUILD_ROOT

###################################
# Base Package with core modules
#
%files
/sbin/sdc-install
/sbin/sdc-firewall

%if 0%{?use_systemd}
%{_unitdir}/sdc-firewall.service
%else
%{_initddir}/sdc-firewall
%endif

%dir %{_sysconfdir}/silentdune
%config(noreplace) %{_sysconfdir}/silentdune/sdc.conf

%dir %{_rundir}/silentdune

%{_sysconfdir}/logrotate.d/silentdune

%{pythonlib}/*.egg-info
%dir %{pythonlib}/silentdune_client
%{pythonlib}/silentdune_client/*.p*
%{pythonlib}/silentdune_client/builders
%{pythonlib}/silentdune_client/init
%{pythonlib}/silentdune_client/models
%{pythonlib}/silentdune_client/po
%{pythonlib}/silentdune_client/utils
%if 0%{?suse_version}
%{pythonlib}/silentdune_client/selinux
%endif

# Top level module directories
%dir %{pythonlib}/silentdune_client/modules
%dir %{pythonlib}/silentdune_client/modules/firewall
%dir %{pythonlib}/silentdune_client/modules/comm
%dir %{pythonlib}/silentdune_client/modules/automation
%{pythonlib}/silentdune_client/modules/*.p*
%{pythonlib}/silentdune_client/modules/firewall/*.p*
%{pythonlib}/silentdune_client/modules/comm/*.p*
%{pythonlib}/silentdune_client/modules/automation/*.p*

# Core Modules
%{pythonlib}/silentdune_client/modules/firewall/manager

# Python 3 Cache directories
%if 0%{?use_python3}

%{pythonlib}/silentdune_client/__pycache__
%{pythonlib}/silentdune_client/modules/__pycache__
%{pythonlib}/silentdune_client/modules/firewall/__pycache__
%{pythonlib}/silentdune_client/modules/comm/__pycache__
%{pythonlib}/silentdune_client/modules/examples/__pycache__
%{pythonlib}/silentdune_client/modules/automation/__pycache__

%endif #0%{?with_python3}

###################################
# https://fedoraproject.org/wiki/Packaging:Scriptlets?rd=Packaging:ScriptletSnippets#Syntax
###################################
%pre
%if 0%{?use_systemd}
%if 0%{?suse_version}
%service_add_pre sdc-firewall.service
%endif
%endif

###################################
%post
%if 0%{?use_systemd}
%if 0%{?suse_version}
%service_add_post sdc-firewall.service
%else
%systemd_post sdc-firewall.service
%endif
%else
%if 0%{?suse_version}
%restart_on_update sdc-firewall
%else
chkconfig --add sdc-firewall
%endif
%endif


###################################
%preun
%if 0%{?use_systemd}
%if 0%{?suse_version}
%service_del_preun -f sdc-firewall.service
%else
%systemd_preun -f sdc-firewall.service
%endif
%else
%if 0%{?suse_version}
%stop_on_removal sdc-firewall
%else
if [ $1 -eq 0 ] ; then
  service sdc-firewall stop > /dev/null 2>&1
  chkconfig --del sdc-firewall > /dev/null 2>&1
fi
%endif
%endif

###################################
%postun
%if 0%{?use_systemd}
%if 0%{?suse_version}
%service_del_postun sdc-firewall.service
%else
%systemd_postun_with_restart sdc-firewall.service
%endif
%else
%if 0%{?suse_version}
%restart_on_update sdc-firewall
%insserv_cleanup
%else
if [ $1 -ge 1 ] ; then
    service sdc-firewall restart >/dev/null 2>&1
fi
%endif
%endif

###################################
# Logging Module
#
%package mod-logging
Requires: silentdune
Summary: Logging module Silent Dune Firewall Service

%description mod-logging
Logging Module for the Silent Dune Firewall Service

%files mod-logging
%{pythonlib}/silentdune_client/modules/firewall/logging

###################################
# Package Examples Module
#
%package mod-examples
Requires: silentdune
Summary: Example modules for Silent Dune Firewall Service

%description mod-examples
Example modules written in python for the Silent Dune Firewall Service

%files mod-examples
%{pythonlib}/silentdune_client/modules/examples

###################################
# Package Silent Dune Server Module
#
%package mod-server
Requires: silentdune silentdune-mod-logging python-requests python-dateutil
Summary: Central Management Module for Silent Dune Firewall Service

%description mod-server
Silent Dune server module allows a system to connect to and be remotely
managed by a Silent Dune server.

%files mod-server
%{pythonlib}/silentdune_client/modules/comm/sd_server

###################################
# Package Remote Config Module
#
%package mod-remoteconfig
Requires: silentdune
%if 0%{?suse_version}
Requires: python-dnspython
%else
Requires: python-dns
%endif

Summary: Remote Config Module for Silent Dune Firewall Service

%description mod-remoteconfig
The Remote Config module for Silent Dune Firewall Service auto allows
a static firewall configuration to be downloaded from a remote URL.

%files mod-remoteconfig
%{pythonlib}/silentdune_client/modules/comm/remote_config

###################################
# Package Auto Discovery Module
#
%package mod-autodiscovery
Requires: silentdune
%if 0%{?suse_version}
Requires: python-dnspython
%else
Requires: python-dns
%endif
Summary: Auto Discovery Module for Silent Dune Firewall Service

%description mod-autodiscovery
The Auto Discovery module for Silent Dune Firewall Service auto detects
local settings and creates ingress and egress firewall rules for external
services like DNS, DHCP, NTP and SSH.

%files mod-autodiscovery
%{pythonlib}/silentdune_client/modules/automation/auto_discovery

###################################
# Package Auto Services Module
#
%package mod-autoservices
Requires: silentdune
Summary: Auto Services Module for Silent Dune Firewall Service

%description mod-autoservices
The Auto Services module for Silent Dune Firewall Service auto detects
services that are accessible externally and creates egress firewall rules
for external them.  Services include Docker containers, Web server and
Database servers.

%files mod-autoservices
%{pythonlib}/silentdune_client/modules/automation/auto_services

####################################
# Package selinux
#
%if (0%{?fedora} || 0%{?rhel})
%package selinux
BuildRequires: selinux-policy-devel selinux-policy-targeted checkpolicy
Requires: silentdune policycoreutils-python
Requires(post):   /usr/sbin/semodule, /sbin/restorecon, /sbin/fixfiles, silentdune
Requires(postun): /usr/sbin/semodule, /sbin/restorecon, /sbin/fixfiles, silentdune

%if "%{_selinux_policy_version}" != ""
Requires: selinux-policy >= %{_selinux_policy_version}
%endif
Summary: SELinux policy for Silent Dune Firewall Service

%description selinux
SELinux policy for Silent Dune Firewall Service

%files selinux
%defattr(-,root,root,0755)
%{pythonlib}/silentdune_client/selinux/*
%doc silentdune_client/selinux/*
%{_datadir}/selinux/*/silentdune.pp

%post selinux

# Add empty directories or files here so they get the right selinux context
touch /var/log/silentdune.log

for selinuxvariant in %{selinux_variants}
do
  /usr/sbin/semodule -s ${selinuxvariant} -i \
    %{_datadir}/selinux/${selinuxvariant}/silentdune.pp &> /dev/null || :
done
/sbin/fixfiles -R silentdune restore || :
#/sbin/restorecon -R %{_localstatedir}/cache/silentdune || :

chcon -R -u system_u -t silentdune_etc_rw_t %{_sysconfdir}/silentdune
chcon -u system_u -t silentdune_var_log_t /var/log/silentdune.log
chcon -R -u system_u -t silentdune_var_run_t %{_rundir}/silentdune

%postun selinux
if [ $1 -eq 0 ] ; then
  for selinuxvariant in %{selinux_variants}
  do
    /usr/sbin/semodule -s ${selinuxvariant} -r silentdune &> /dev/null || :
  done
  /sbin/fixfiles -R silentdune restore || :
  [ -d %{_localstatedir}/cache/silentdune ]  && \
    /sbin/restorecon -R %{_localstatedir}/cache/silentdune &> /dev/null || :
fi
%endif  # 0%{?fedora} || 0%{?rhel}
