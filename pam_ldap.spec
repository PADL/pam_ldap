Summary: LDAP Pluggable Authentication Module
Name: pam_ldap
Version: 62
Release: 7
Source: ftp://ftp.padl.com/pub/pam_ldap-%{version}.tar.gz
URL: http://www.padl.com/
Copyright: LGPL
Group: System Environment/Base
BuildRoot: /var/tmp/%{name}-root

%description 
This is pam_ldap, a pluggable authentication module that can be used
with linux-PAM. This module supports password changes, V2 clients,
Netscapes SSL, ypldapd, Netscape Directory Server password policies,
access authorization, crypted hashes, etc.

%prep
%setup -q

%build
touch NEWS AUTHORS
./configure --prefix=$RPM_BUILD_ROOT

%install
rm -rf $RPM_BUILD_ROOT
make install
mkdir -p $RPM_BUILD_ROOT/etc
install -m 644 ldap.conf $RPM_BUILD_ROOT/etc/ldap.conf

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/lib/security/pam_ldap.so
%config(noreplace) /etc/ldap.conf
%doc README COPYING.LIB ChangeLog ldap.conf pam.d

%changelog
* Thu Jun 22 2000 Dan Berry <dberry@boomshanka.ab.ca>
- updated the RPM spec properly for GNU configure and version 61

* Wed Jan 26 2000 Daniel Hanks <hanksdc@plug.org>
- updated the RedHat spec file for version 43

* Tue Aug 10 1999 Cristian Gafton <gafton@redhat.com>
- adapted the original spec file for RH 6.1
- ship the same config file as the nss_ldap


