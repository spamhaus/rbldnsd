#! /usr/bin/make -rf
#
# $Id$
# Makefile for rbldnsd

CC = cc
CFLAGS = -O
LD = $(CC)
LDFLAGS = $(CFLAGS)
AR = ar
ARFLAGS = rv
RANLIB = :
SHELL = /bin/sh -e
AWK = awk

# Disable statistic counters
#DEFS = -DNOSTATS
# Disable memory info logging (mallinfo)
#DEFS = -DNOMEMINFO
# Disable printing zone (re)load time using utimes()
#DEFS = -DNOTIMES
# If your system lacks <stdint.h> header but uint32_t is in sys/types.h
#DEFS = -DNOSTDINT_H
# If you don't want/have IPv6 support (transport only)
#DEFS = -DNOIPv6
# For FreeBSD 4.4 use DEFS="-DNOMEMINFO -DNOSTDINT_H"

SOCKET_LIBS = `[ -f /usr/lib/libsocket.so ] && echo -lsocket -lnsl || :`

LIBDNS_SRCS = dns_ptodn.c dns_dntop.c dns_dntol.c dns_dnlen.c dns_dnlabels.c \
 dns_dnreverse.c dns_findname.c
LIBDNS_GSRC = dns_nametab.c
LIBDNS_HDRS = dns.h
LIBDNS_OBJS = $(LIBDNS_SRCS:.c=.o) $(LIBDNS_GSRC:.c=.o)

LIBIP4_SRCS = ip4parse.c ip4atos.c ip4mask.c
LIBIP4_GSRC =
LIBIP4_HDRS = ip4addr.h
LIBIP4_OBJS = $(LIBIP4_SRCS:.c=.o)

LIB_SRCS = $(LIBDNS_SRCS) $(LIBIP4_SRCS) mempool.c
LIB_HDRS = $(LIBDNS_HDRS) $(LIBIP4_HDRS) mempool.h
LIB_OBJS = $(LIBDNS_OBJS) $(LIBIP4_OBJS) mempool.o
LIB_GSRC = $(LIBDNS_GSRC) $(LIBIP4_GSRC)

RBLDNSD_SRCS = rbldnsd.c rbldnsd_zones.c rbldnsd_packet.c \
  rbldnsd_ip4set.c rbldnsd_dnset.c rbldnsd_generic.c rbldnsd_util.c
RBLDNSD_HDRS = rbldnsd.h
RBLDNSD_OBJS = $(RBLDNSD_SRCS:.c=.o) librbldnsd.a

MISC = rbldnsd.8 qsort.c Makefile NEWS CHANGES WirehubDynablock2rbldnsd.pl

SRCS = $(LIB_SRCS) $(RBLDNSD_SRCS) ip4rangetest.c
GSRC = $(LIB_GSRC)
HDRS = $(LIB_HDRS) $(RBLDNSD_HDRS)

VERSION = `sed -e 's/^[^(]*(\([^)]*\)).*/\1/' -e 1q debian/changelog`
VERSION_DATE = `sed -n '/^ --/ { s/.*  ...,  \{0,1\}\([0-9]\{1,2\} ... [0-9]\{4\}\) .*/\1/p; q; }' debian/changelog`

all: rbldnsd

rbldnsd: $(RBLDNSD_OBJS)
	$(LD) $(LDFLAGS) -o $@ $(RBLDNSD_OBJS) $(SOCKET_LIBS)

librbldnsd.a: $(LIB_OBJS)
	-rm -f $@
	$(AR) $(ARFLAGS) $@ $(LIB_OBJS)
	$(RANLIB) $@

ip4rangetest: ip4rangetest.o ip4parse.o
	$(LD) $(LDFLAGS) -o $@ ip4rangetest.o ip4parse.o

.SUFFIXES: .c .o

COMPILE = $(CC) $(CFLAGS) $(DEFS) -c $<

.c.o:
	$(COMPILE)

dns_nametab.c: dns.h dns_maketab.awk
	$(AWK) -f dns_maketab.awk dns.h > $@.tmp
	mv -f $@.tmp $@

rbldnsd.o: rbldnsd.c debian/changelog
	@echo
	@echo \ rbldnsd VERSION="\"$(VERSION) ($(VERSION_DATE))\""
	@echo
	$(COMPILE) -DVERSION="\"$(VERSION) ($(VERSION_DATE))\""

clean:
	-rm -f $(RBLDNSD_OBJS) $(LIB_OBJS) librbldnsd.a ip4rangetest $(GSRC) \
		ip4rangetest.o
distclean: clean
	-rm -f rbldnsd

spec: rbldnsd.spec
rbldnsd.spec: rbldnsd.spec.in debian/changelog
	sed -e '1,/^$$/ D' -e "s/@VERSION@/$(VERSION)/" rbldnsd.spec.in > $@.tmp
	mv $@.tmp $@

depend dep deps: $(SRCS) $(GSRC)
	@echo Generating deps for:
	@echo \ $(SRCS) $(GSRC)
	@sed '/^# depend/q' Makefile > Makefile.tmp
	@$(CC) $(CFLAGS) -MM $(SRCS) $(GSRC) >> Makefile.tmp
	@if cmp Makefile.tmp Makefile ; then \
	  echo Makefile unchanged; \
	  rm -f Makefile.tmp; \
	else \
	  echo Updating Makfile; \
	  mv -f Makefile.tmp Makefile ; \
	fi

# depend
dns_ptodn.o: dns_ptodn.c dns.h
dns_dntop.o: dns_dntop.c dns.h
dns_dntol.o: dns_dntol.c dns.h
dns_dnlen.o: dns_dnlen.c dns.h
dns_dnlabels.o: dns_dnlabels.c dns.h
dns_dnreverse.o: dns_dnreverse.c dns.h
dns_findname.o: dns_findname.c dns.h
ip4parse.o: ip4parse.c ip4addr.h
ip4atos.o: ip4atos.c ip4addr.h
ip4mask.o: ip4mask.c ip4addr.h
mempool.o: mempool.c mempool.h
rbldnsd.o: rbldnsd.c rbldnsd.h ip4addr.h dns.h mempool.h
rbldnsd_zones.o: rbldnsd_zones.c rbldnsd.h ip4addr.h dns.h mempool.h
rbldnsd_packet.o: rbldnsd_packet.c rbldnsd.h ip4addr.h dns.h mempool.h
rbldnsd_ip4set.o: rbldnsd_ip4set.c rbldnsd.h ip4addr.h dns.h mempool.h \
 qsort.c
rbldnsd_dnset.o: rbldnsd_dnset.c rbldnsd.h ip4addr.h dns.h mempool.h \
 qsort.c
rbldnsd_generic.o: rbldnsd_generic.c rbldnsd.h ip4addr.h dns.h \
 mempool.h qsort.c
rbldnsd_util.o: rbldnsd_util.c rbldnsd.h ip4addr.h dns.h mempool.h
ip4rangetest.o: ip4rangetest.c ip4addr.h rbldnsd.h dns.h mempool.h
dns_nametab.o: dns_nametab.c dns.h
