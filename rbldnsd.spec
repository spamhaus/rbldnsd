# $Id$
# RPM spec file for rbldnsd

Summary: Small fast daemon to serve DNSBLs
Name: rbldnsd
Version: 0.91pre
Release: 1
License: GPL
Group: System Environment/Daemons
BuildRoot: %_tmppath/%name-%version
PreReq: /sbin/chkconfig, shadow-utils

Source: http://www.corpit.ru/mjt/%name/%{name}_%version.tar.gz

%define home /var/lib/rbldns

%description
Rbldnsd is a small authoritate-only DNS nameserver
designed to serve DNS-based blocklists (DNSBLs).
It may handle IP-based and name-based blocklists.

%prep
%setup -q -n %name-%version

%build
make CFLAGS="$RPM_OPT_FLAGS" CC="${CC:-%__cc}"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT{%_sbindir,%_mandir/man8,/etc/init.d,/etc/sysconfig}
mkdir -p $RPM_BUILD_ROOT%home
cp rbldnsd $RPM_BUILD_ROOT%_sbindir/
cp -p rbldnsd.8 $RPM_BUILD_ROOT%_mandir/man8/
cp -p debian/rbldnsd.default $RPM_BUILD_ROOT/etc/sysconfig/rbldnsd
cp -p debian/rbldnsd.init $RPM_BUILD_ROOT/etc/init.d/rbldnsd
chmod +x $RPM_BUILD_ROOT/etc/init.d/rbldnsd

%clean
rm -rf $RPM_BUILD_ROOT

%post
getent passwd rbldns ||
  useradd -r -d %home -M -c "rbldnsd pseudo-user" -s /sbin/nologin rbldns
/sbin/chkconfig --add rbldnsd
/etc/init.d/rbldnsd restart

%preun
if [ $1 -eq 0 ]; then
   /etc/init.d/rbldnsd stop || :
   /sbin/chkconfig --del rbldnsd
   userdel rbldns || :
fi

%files
%defattr (-,root,root)
%doc NEWS TODO debian/changelog CHANGES-0.81 WirehubDynablock2rbldnsd.pl
%_sbindir/rbldnsd
%_mandir/man8/rbldnsd.8*
%config(noreplace) /etc/sysconfig/rbldnsd
/etc/init.d/rbldnsd
%home
