# $Id$
# RPM spec template for rbldnsd

Summary: Small fast daemon to serve DNSBLs
Name: rbldnsd
Version: @VERSION@
Release: 1
License: GPL
Group: System Environment/Daemons
BuildRoot: %_tmppath/%name-%version

Source: http://www.corpit.ru/mjt/%name/%name-%version.tar.gz

%description
Rbldnsd is a small authoritate-only DNS nameserver
designed to serve DNS-based blocklists (DNSBLs).
It may handle IP-based and name-based blocklists.

%prep
%setup -q -n %name-%version

%build
make CFLAGS="$RPM_OPT_FLAGS" CC="$CC"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT{%_sbindir,%_mandir/man8,/etc/init.d,/etc/sysconfig}
cp rbldnsd $RPM_BUILD_ROOT%_sbindir/
cp -p rbldnsd.8 $RPM_BUILD_ROOT%_mandir/man8/
cp -p debian/rbldnsd.default $RPM_BUILD_ROOT/etc/sysconfig/rbldnsd
cp -p debain/rbldnsd.init $RPM_BUILD_ROOT/etc/init.d/rbldnsd

%files
%defattr (-,root,root)
%doc NEWS TODO debian/changelog CHANGES-0.81 WirehubDynablock2rbldnsd.pl
%_sbindir/rbldnsd
%_mandir/man8/rbldnsd.8*
%config(noreplace) /etc/sysconfig/rbldnsd
