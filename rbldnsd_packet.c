/* $Id$
 * DNS packet handling routines for rbldnsd
 */

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "rbldnsd.h"
#include "rbldnsd_zones.h"
#include "dns.h"

/* DNS packet:
 * 0:1   identifier (client supplied)
 * 2     flags1
 *  0x80 QR response flag
 *  0x78 opcode: 0 query
 *  0x04 AA auth answer
 *  0x02 TC truncation flag
 *  0x01 RD recursion desired (may be set in query)
 * 3     flags2
 *  0x80 RA recursion available
 *  0x70 Z reserved
 *  0x0f RCODE:
 *     0 ok, 1 format error, 2 servfail, 3 nxdomain, 4 notimpl, 5 refused
 * 4:5   qdcount (numqueries)
 * 6:7   ancount (numanswers)
 * 8:9   nscount (numauthority)
 * 10:11 arcount (numadditional)
 * next is a DN name, a series of labels with first byte is label's length,
 *  terminated by zero-length label (i.e. at least one zero byte is here)
 * next two bytes are query type (A, SOA etc)
 * next two bytes are query class (IN, HESIOD etc)
 */

int replypacket(struct dnspacket *p, unsigned qlen, const struct zone *zone) {

  /* parsing incoming query.  Untrusted data read directly from the network.
   * p->p is a buffer - data that was read (DNS_MAXPACKET max).
   * len is number of bytes actually read (query length)
   * first 12 bytes is header, next is query DN,
   * next are QTYPE and QCLASS (2x2 bytes).
   * rest of data if any is ignored.
   */

  unsigned qcls, qtyp;			/* query qclass and qtype */
  unsigned qlab;			/* number of labels in qDN */
  unsigned char qdn[DNS_MAXDN];		/* lowercased version of qDN */

#define DNS_MAXLAB (DNS_MAXDN/2)	/* maximum number of labels in a DN */
  unsigned char *qlp[DNS_MAXLAB];	/* labels: pointers to qdn[] */
  int nmatch, nfound;

  register unsigned char *const q = p->p;	/* start of query */
  unsigned char *x;

  x = q + qlen - 5;	/* last possible qDN zero terminator position */
  /* qlen isn't needed anymore, it'll be used as length of qDN below */

  if (q + 12 > x)
    return 0; /* short packet (header isn't here) */
  else if (q + 12 + DNS_MAXDN <= x)
    x = q + 12 + DNS_MAXDN - 1; /* constrain query DN to DNS_MAXDN */

  if (q[2] & 0x80) return 0; /* response?! */
  if (q[4] || q[5] != 1) return 0; /* qdcount != 1 */

  {	/* parse and lowercase query DN, count labels */
    register unsigned char *s = q + 12;	/* orig src DN in question (<= x) */
    register unsigned char *d = qdn;	/* dest lowercased ptr */
    register unsigned char *e;		/* end of current label */
    qlab = DNS_MAXLAB;
    while((qlen = (*d++ = *s++)) != 0) { /* loop by DN lables */
      if (qlen > DNS_MAXLABEL || (e = s + qlen) > x) return 0;
      qlp[--qlab] = d - 1;
      do *d++ = dns_dnlc(*s);	/* lowercase current label */
      while (++s < e);		/* ..until it's end */
    }
    qlen = d - qdn;
    qtyp = ((unsigned)(s[0]) << 8) | s[1];
    qcls = ((unsigned)(s[2]) << 8) | s[3];
    p->c = p->sans = s + 4; /* answers will start here */
    qlab = DNS_MAXLAB - qlab;
  }

  /* from now on, we see (almost?) valid dns query, should reply */
  p->nans = 0;

#define refuse(code) (q[2] = 0x84, q[3] = (code), (p->sans - q))

  /* construct reply packet */
  /* identifier already in place */
  /* flags will be set up later */
  /* q[4:5] (qdcount) already set up in query */
  q[6] = q[7] = 0; /* ancount */
  q[8] = q[9] = 0; /* nscount */
  q[10] = q[11] = 0; /* arcount */

  if (qcls != DNS_C_IN && qcls != DNS_C_ANY)
    return refuse(DNS_C_FORMERR);
  if (q[2] & 126)
    return refuse(DNS_C_NOTIMPL);
  switch(qtyp) {
  case DNS_T_ANY: qtyp = NSQUERY_ANY; break;
  case DNS_T_A:   qtyp = NSQUERY_A; break;
  case DNS_T_TXT: qtyp = NSQUERY_TXT; break;
  case DNS_T_NS:  qtyp = NSQUERY_NS; break;
  case DNS_T_SOA: qtyp = NSQUERY_SOA; break;
  default: return refuse(DNS_C_REFUSED);
  }

  q[2] = 0x80; /* 0x81?! */
  if (qcls == DNS_C_IN) q[2] |= 0x04; /* AA */
  q[3] = DNS_C_NOERROR;

  nmatch = nfound = 0;

  for(; zone; zone = zone->next) {
    register const struct zonedatalist *zdl;

    if (!zone->loaded) continue;
    if (zone->dnlab > qlab) continue;
    x = qlp[DNS_MAXLAB - 1 - qlab + zone->dnlab];
    if (zone->dnlen != qlen - (x - qdn)) continue;
    if (memcmp(zone->dn, x, zone->dnlen) != 0) continue;

    *x = 0;	/* terminate dn to end at zone base dn */
    for(zdl = zone->dlist; zdl; zdl = zdl->next)
      if (zdl->set->qfilter & qtyp) {
        nmatch = 1;	/* at least one zone with this data types */
        if (zdl->set->queryfn(zdl->set->data, p, qdn, qtyp))
          nfound = 1;	/* positive answer */
      }
    *x = zone->dn[0];	/* restore qdn */

  }

  if (nfound) {
    q[6] = p->nans >> 8; q[7] = p->nans;
    return p->c - q;
  }
  else if (nmatch) {
    q[2] = 0x84; q[3] = DNS_C_NXDOMAIN;
    return p->sans - q;
  }
  else
    return refuse(DNS_C_REFUSED);
}

static int aexists(const struct dnspacket *p, unsigned typ,
                   const void *val, unsigned vlen) {
  const unsigned char *c, *e;
  for(c = p->sans, e = p->c; c < e; c = c + 12 + c[11]) {
    if (c[2] == (typ>>8) && c[3] == (typ&255) &&
        c[11] == vlen && memcmp(c + 12, val, vlen) == 0)
      return 1;
  }
  return 0;
}

int addrec_any(struct dnspacket *p, unsigned dtp,
               const void *data, unsigned dsz) {
  if (p->c + 12 + dsz >= p->p + sizeof(p->p)) return 0;
  if (aexists(p, dtp, data, dsz)) return 0;
  p->nans++;
  *p->c++ = 192; *p->c++ = 12; /* jump after header */
  *p->c++ = dtp >> 8; *p->c++ = dtp; /* dtype */
  *p->c++ = DNS_C_IN>>8; *p->c++ = DNS_C_IN; /* class */
  *p->c++ = defttl>>24; *p->c++ = defttl>>16;
  *p->c++ = defttl>>8; *p->c++ = defttl;
  *p->c++ = dsz>>8; *p->c++ = dsz; /* dsize */
  memcpy(p->c, data, dsz);
  p->c += dsz;
  return 1;
}

int
addrec_a(struct dnspacket *p, ip4addr_t aip) {
  aip = htonl(aip);
  return addrec_any(p, DNS_T_A, &aip, 4);
}

int
addrec_txt(struct dnspacket *p, const char *txt, const char *subst) {
  unsigned sl;
  char sb[256];
  char *lp, *s, *const e = sb + 254;
  if (!txt) return 0;
  if (p->c + 13 >= p->p + sizeof(p->p)) return 0;
  lp = sb + 1;
  if (!subst) subst = "$";
  while(lp < e) {
    if ((s = strchr(txt, '$')) == NULL)
      s = (char*)txt + strlen(txt);
    sl = s - txt;
    if (lp + sl > e)
      sl = e - lp;
    memcpy(lp, txt, sl);
    lp += sl;
    if (!*s) break;
    sl = strlen(subst);
    if (lp + sl > e)
      sl = e - lp;
    memcpy(lp, subst, sl);
    lp += sl;
    txt = s + 1;
  }
  sl = lp - sb;
  sb[0] = sl - 1;
  return addrec_any(p, DNS_T_TXT, sb, sl);
}

void logreply(const struct dnspacket *pkt, const char *ip, FILE *flog) {
  char domain[DNS_MAXDOMAIN+1];
  const unsigned char *p;
  unsigned q;
  char *v;

  p = pkt->p + 12;
  dns_dntop(p, domain, sizeof(domain));
  p += dns_dnlen(p);
  fprintf(flog, "%lu %s %s ", (unsigned long)time(NULL), ip, domain);

  q = ((unsigned)p[0]<<8)|p[1];
  switch(q) {
  case DNS_T_A:     v = "A"; break;
  case DNS_T_TXT:   v = "TXT"; break;
  case DNS_T_NS:    v = "NS"; break;
  case DNS_T_SOA:   v = "SOA"; break;
  case DNS_T_MX:    v = "MX"; break;
  case DNS_T_AAAA:  v = "AAAA"; break;
  case DNS_T_CNAME: v = "CNAME"; break;
  case DNS_T_PTR:   v = "PTR"; break;
  case DNS_T_ANY:   v = "ANY"; break;
  default: fprintf(flog, "type0x%x ", q); v = NULL;
  }
  if (v) fprintf(flog, "%s ", v);

  q = ((unsigned)p[2]<<8)|p[3];
  switch(q) {
  case DNS_C_IN: v = "IN"; break;
  case DNS_C_ANY: v = "ANY"; break;
  default: fprintf(flog, "cls0x%x: ", q); v = NULL;
  }
  if (v) fprintf(flog, "%s: ", v);

  p = pkt->p;
  q = p[3];
  switch(q) {
  case DNS_C_NOERROR:  v = "NOERROR";  break;
  case DNS_C_FORMERR:  v = "FORMERR";  break;
  case DNS_C_SERVFAIL: v = "SERVFAIL"; break;
  case DNS_C_NXDOMAIN: v = "NXDOMAIN"; break;
  case DNS_C_NOTIMPL:  v = "NOTIMPL";  break;
  case DNS_C_REFUSED:  v = "REFUSED";  break;
  default: fprintf(flog, "code%u", q); v = NULL;
  }
  if (v) fprintf(flog, "%s", v);
  fprintf(flog, "/%u/%d\n", pkt->nans, pkt->c - pkt->p);
  fflush(flog);
}
