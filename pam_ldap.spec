Summary: LDAP Pluggable Authentication Module
Name:      pam_ldap
Version:   45
Release:   1
Source:    ftp://ftp.padl.com/pub/%{name}-%{version}.tar.gz
URL:       http://www.padl.com/
Copyright: GLPL
Group: Libraries
BuildRoot: /tmp/rpm-%{name}-root

%description 
This is a pam_ldap module. Supports password changes, V2 clients,
Netscapes SSL, ypldapd, Netscape Directory Server password
policies, access authorization, crypted hashes, etc. 


%prep
export RPM_BUILD_ROOT
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/lib
mkdir -p $RPM_BUILD_ROOT/lib/security
mkdir -p $RPM_BUILD_ROOT/etc

%setup

%build
make -f Makefile.linux

%install
make -f Makefile.linux install

%clean
rm -rf $RPM_BUILD_ROOT

%files
/lib/security

%doc README
%doc COPYING.LIB
%doc ChangeLog
%doc pam.conf
%doc ldap.conf
%doc pam.d
