Summary: LDAP Pluggable Authentication Module
Name: pam_ldap
Version: 51
Release: 6
Source0: ftp://ftp.padl.com/pub/pam_ldap-%{version}.tar.gz
Source1: ldap.conf
URL: http://www.padl.com/
Copyright: LGPL
Group: System Environment/Base
BuildRoot: /var/tmp/%{name}-root

%description 
This is pam_ldap, a pluggable authentication module that can be used with
linux-PAM. This module supports password changes, V2 clients, Netscapes SSL,
ypldapd, Netscape Directory Server password policies, access authorization,
crypted hashes, etc.

%prep
%setup -q

%build
make -f Makefile.linux

%install
rm -rf $RPM_BUILD_ROOT
make -f Makefile.linux install
mkdir -p $RPM_BUILD_ROOT/etc
install -m 644 %{SOURCE1} $RPM_BUILD_ROOT/etc/ldap.conf

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/lib/security/pam_ldap.so
%config(noreplace) /etc/ldap.conf
%doc README COPYING.LIB ChangeLog ldap.conf pam.d

%changelog
* Wed Jan 26 2000 Daniel Hanks <hanksdc@plug.org>
- updated the RedHat spec file for version 43

* Tue Aug 10 1999 Cristian Gafton <gafton@redhat.com>
- adapted the original spec file for RH 6.1
- ship the same config file as the nss_ldap

