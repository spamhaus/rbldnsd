/* $Id$
 * common #include file for dns library.
 */

#ifndef DNS_PORT

#define DNS_PORT 53
#define DNS_MAXPACKET 512
#define DNS_MAXDN 255
#define DNS_MAXLABEL 63
#define DNS_MAXDOMAIN 1024

enum dns_class {
  DNS_C_INVALID	= 0x0000, /* invalid class */
  DNS_C_IN	= 0x0001, /* Internet */
  DNS_C_CH	= 0x0003, /* CHAOS */
  DNS_C_HS	= 0x0004, /* HESIOD */
  DNS_C_ANY	= 0x00ff  /* wildcard */
};

enum dns_rtype {
  DNS_T_INVALID	= 0x0000, /* invalid rtype */
  DNS_T_A	= 0x0001, /* IPv4 host address, 4 bytes in NBO */
  DNS_T_NS	= 0x0002, /* nameserver, dn */
  DNS_T_CNAME	= 0x0005, /* alias (canonical name), dn */
  DNS_T_SOA	= 0x0006, /* start of authority */
  DNS_T_PTR	= 0x000c, /* domain name pointer, dn */
  DNS_T_MX	= 0x000f, /* mail exchanger, preference and dn */
  DNS_T_TXT	= 0x0010, /* text string */
  DNS_T_AAAA	= 0x001c, /* IPv6 host address */
  DNS_T_TSIG	= 0x00fa, /* transaction signature */
  DNS_T_IXFR	= 0x00fb, /* incremental zone transfer */
  DNS_T_AXFR	= 0x00fc, /* transfer zone of authority */
  DNS_T_MAILB	= 0x00fd, /* transfer mailbox records */
  DNS_T_MAILA	= 0x00fe, /* transfer mail agent records */
  DNS_T_ANY	= 0x00ff  /* any, wildcard */
};

enum dns_rcode {	/* reply code */
  DNS_C_NOERROR		= 0,	/* ok, no error */
  DNS_C_FORMERR		= 1,	/* format error */
  DNS_C_SERVFAIL	= 2,	/* server failed */
  DNS_C_NXDOMAIN	= 3,	/* domain does not exists */
  DNS_C_NOTIMPL		= 4,	/* not implemented */
  DNS_C_REFUSED		= 5	/* query refused */
};

unsigned dns_ptodn(const char *name, unsigned char *dn, unsigned dnsiz);
/* convert asciiz string `name' to the DN format, return length or 0 */
unsigned dns_dntop(const unsigned char *dn, char *dst, unsigned dstsiz);
unsigned dns_dntol(const unsigned char *srcdn, unsigned char *dstdn);
#define dns_dnlc(c) ((c) >= 'A' && (c) <= 'Z' ? (c) - 'A' + 'a' : (c))
unsigned dns_dnlen(const unsigned char *dn);
unsigned dns_dnlabels(const unsigned char *dn);
unsigned dns_dnreverse(const unsigned char *dn, unsigned char *rdn);


#endif
