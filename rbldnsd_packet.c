/* $Id$
 * DNS packet handling routines for rbldnsd
 */

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "rbldnsd.h"
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

static int add_soa(struct dnspacket *p, const struct zone *zone, int auth);

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

  register unsigned char *const q = p->p;	/* start of query */
  unsigned char *x;

  int found;

  struct dnsquery query;

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
    register unsigned char *d = query.q_dn; /* dest lowercased ptr */
    register unsigned char *e;		/* end of current label */
    qlab = 0;
    while((qlen = (*d++ = *s++)) != 0) { /* loop by DN lables */
      if (qlen > DNS_MAXLABEL || (e = s + qlen) > x) return 0;
      ++qlab;			/* yet another label */
      do *d++ = dns_dnlc(*s);	/* lowercase current label */
      while (++s < e);		/* ..until it's end */
    }
    qlen = d - query.q_dn;	/* d points past the end of qdn now */

    /* s is end of qdn. decode qtype and qclass, and prepare for an answer */
    qtyp = ((unsigned)(s[0]) << 8) | s[1];
    qcls = ((unsigned)(s[2]) << 8) | s[3];
    p->c = p->sans = s + 4; /* answers will start here */
  }

  /* from now on, we see (almost?) valid dns query, should reply */
  /* vars still in use:
   *  p (packet); q (it's p->p); qlen, qlab; qtyp, qcls */

#define refuse(code) (q[2] = 0x84, q[3] = (code), (p->sans - q))
#define setnonauth(q) (q[2] &= ~0x04)

  /* construct reply packet */
  /* identifier already in place */
  /* flags will be set up later */
  /* q[4:5] (qdcount) already set up in query */
  q[6] = q[7] = 0; /* ancount (<255) */
  q[8] = q[9] = 0; /* nscount (<255) */
  q[10] = q[11] = 0; /* arcount (<255) */

  if (qcls != DNS_C_IN && qcls != DNS_C_ANY)
    return refuse(DNS_R_FORMERR);
  if (q[2] & 126)
    return refuse(DNS_R_NOTIMPL);
  switch(qtyp) {
  case DNS_T_ANY: qtyp = NSQUERY_ANY; break;
  case DNS_T_A:   qtyp = NSQUERY_A; break;
  case DNS_T_TXT: qtyp = NSQUERY_TXT; break;
  case DNS_T_NS:  qtyp = NSQUERY_NS; break;
  case DNS_T_SOA: qtyp = NSQUERY_SOA; break;
  case DNS_T_MX:  qtyp = NSQUERY_MX; break;
  default:
    if (qtyp != DNS_T_INVALID && qtyp < DNS_T_TSIG)
      qtyp = NSQUERY_OTHER;
    else
      return refuse(DNS_R_REFUSED);
  }

  q[2] = 0x80;
  if (qcls == DNS_C_IN) q[2] |= 0x04; /* AA */
  q[3] = DNS_R_NOERROR;

  /* make reverse of qdn */
  dns_dnreverse(query.q_dn, query.q_rdn_b, qlen);

  /* find matching zone */
  for(;; zone = zone->z_next) {
    if (!zone) /* not authoritative */
      return refuse(DNS_R_REFUSED);
    if (zone->z_dnlen <= qlen &&
        memcmp(zone->z_rdn, query.q_rdn_b, zone->z_dnlen - 1) == 0)
      break;
  }

  /* found matching zone */
  if (!zone->z_stamp)	/* do not answer if not loaded */
    return refuse(DNS_R_SERVFAIL);

  /* initialize query */
  query.q_dnlen = (qlen -= zone->z_dnlen - 1);
  query.q_dn[qlen - 1] = '\0';
  query.q_rdn = query.q_rdn_b + zone->z_dnlen - 1;
  query.q_dnlab = (qlab -= zone->z_dnlab);
  query.q_type = qtyp;

  found = qlab == 0;	/* no NXDOMAIN if it's a query for the zone base DN */
  /* vars still in use:
   *  p (packet struct); q (p->p); qlab is #of labels w/o zone dn;
   *  qtyp (converted to a bitmask); found (flag - if we found smth) */

  /* initialize various query variations */
  if (zone->z_dstflags & DSTF_IP4REV) /* ip4 address */
    query.q_ip4oct =
      qlab && qlab <= 4 ? dntoip4addr(query.q_dn, &query.q_ip4) : 0;

  { /* initialize DN compression */
    /* start at zone DN, not at query DN, as it may contain
     * unnecessary long DN.  Zone DN should fit in compr array */
    struct dnsdnptr *ptr = p->compr.ptr;
    unsigned qpos = (p->sans - 4 - (qlen = zone->z_dnlen)) - p->p;
    x = zone->z_dn;
    while((qcls = *x)) {
      ++qcls;
      ptr->dnlen = qlen; qlen -= qcls;
      ptr->qpos = qpos; qpos += qcls;
      ptr->dnp = x; x += qcls;
      ++ptr;
    }
    p->compr.cptr = ptr;
    p->compr.cdnp = p->compr.dnbuf;
  }

  /* search the datasets */
  { register const struct zonedatalist *zdl;
    for(zdl = zone->z_zdl; zdl; zdl = zdl->zdl_next)
      if (zdl->zdl_queryfn(zdl->zdl_ds, &query, p))
        found = 1;	/* positive answer */
  }

  /* XXXXXXXXXXX check logic here!!! */
  /* Notes.
   *  - If query is zone's dn itself (qlab == 0), we can't return NXDOMAIN,
   *    since it cleanly does exists.  At best we can return positive answer
   *    with zero RRs.
   *  - SOA is special.  I'm not sure whenever it's ok to return positive
   *    reply with 0 RRs for SOA qieries to base DN - maybe REFUSE is better?
   *    At least, DJB's rbldns refuses SOA and NS requests altogether.
   *  - ANY query and SOA/NS: if there is no SOA/NS specified?  Refuse?!
   *  - Also, SOA of base zone should be added to ADDITIONAL section for
   *    every answer (except of base dn's SOA itself)
   */
  if (!found) { /* not found, and query isn't base DN */
    add_soa(p, zone, 1); /* for negative query, add SOA to AUTHORITY */
    q[3] = DNS_R_NXDOMAIN;
  }
  else if (!qlab && qtyp & NSQUERY_SOA)
    add_soa(p, zone, 0); /* query to base dn, ANY or SOA => add SOA to ANSWER */
  else if (!q[7]) /* positive reply, 0 answers => add SOA if any to AUTHORITY */
    add_soa(p, zone, 1);
  return p->c - q;
}

#define fit(p, c, bytes) ((c) + (bytes) <= (p)->p + DNS_MAXPACKET)

/* adds 8 bytes */
#define addrr_rrstart(c,type,ttl)		\
    *(c)++ = type>>8; *(c)++ = type;		\
    *(c)++ = DNS_C_IN>>8; *(c)++ = DNS_C_IN;	\
    memcpy((c), ttl, 4); (c) += 4

/* adds 10 bytes */
#define addrr_start(c,type,ttl)				\
    *(c)++ = 192; *(c)++ = 12; /* jump after header */	\
    addrr_rrstart((c),type,ttl)

static unsigned char *
add_dn(struct dnspacket *p, register unsigned char *c,
       const unsigned char *dn, unsigned dnlen) {
  struct dnsdnptr *ptr;
  while(*dn) {
    for(ptr = p->compr.ptr; ptr < p->compr.cptr; ++ptr) {
      if (ptr->dnlen != dnlen || memcmp(ptr->dnp, dn, dnlen) != 0)
        continue;
      if (!fit(p, c, 2)) return NULL;
      dnlen = 0xc000 + ptr->qpos;
      *c++ = dnlen >> 8; *c++ = dnlen;
      return c;
    }
    if (!fit(p, c, *dn + 1))
      return NULL;
    if (dnlen < 128 &&
        p->compr.cdnp + dnlen <= p->compr.dnbuf + sizeof(p->compr.dnbuf) &&
        ptr < p->compr.ptr + DNS_MAXDN/2) {
      ptr->dnp = p->compr.cdnp; p->compr.cdnp += dnlen;
      ptr->dnlen = dnlen;
      ptr->qpos = c - p->p;
      ++p->compr.cptr;
    }
    memcpy(c, dn, *dn + 1);
    c += *dn + 1;
    dnlen -= *dn + 1;
    dn += *dn + 1;
  }
  if (!fit(p, c, 1)) return NULL;
  *c++ = '\0';
  return c;
}

static int add_soa(struct dnspacket *p, const struct zone *zone, int auth) {
  register unsigned char *c;
  unsigned char *rstart;
  unsigned dsz;
  struct dnsdnptr *cdnptr;
  if (!zone->z_zsoa.zsoa_valid) {
    if (!auth)
      setnonauth(p->p); /* non-auth answer as we can't fit the record */
    return 0;
  }
  c = p->c;
  cdnptr = p->compr.cptr; /* save current compression pointer */
  if ((c = add_dn(p, c, zone->z_dn, zone->z_dnlen)) && fit(p, c, 8 + 2)) {
    /* 8 bytes */
    addrr_rrstart(c, DNS_T_SOA,
            (auth ? zone->z_zsoa.zsoa_n + 16 : (unsigned char*)&defttl_nbo));
    rstart = c;
    c += 2;
    if ((c = add_dn(p, c, zone->z_zsoa.zsoa_odn+1, zone->z_zsoa.zsoa_odn[0])) &&
        (c = add_dn(p, c, zone->z_zsoa.zsoa_pdn+1, zone->z_zsoa.zsoa_pdn[0])) &&
        fit(p, c, 20)) {
      memcpy(c, &zone->z_zsoa.zsoa_n, 20);
      c += 20;
      dsz = (c - rstart) - 2;
      rstart[0] = dsz >> 8; rstart[1] = dsz;
      p->p[auth ? 9 : 7]++;
      p->c = c;
      return 1;
    }
  }
  p->compr.cptr = cdnptr; /* probably unnecessary: SOA is last RR */
  setnonauth(p->p); /* non-auth answer as we can't fit the record */
  return 0;
}

int addrec_ns(struct dnspacket *p, 
              const unsigned char *nsdn, unsigned nsdnlen) {
  register unsigned char *c = p->c;
  if (fit(p, c, 10 + 2)) {
    addrr_start(c, DNS_T_NS, &defttl_nbo); /* 10 bytes */
    c += 2;
    if ((c = add_dn(p, c, nsdn, nsdnlen))) {
      nsdnlen = (c - p->c) - 12;
      p->c[10] = nsdnlen>>8; p->c[11] = nsdnlen;
      p->c = c;
      p->p[7] += 1;
      return 1;
    }
  }
  setnonauth(p->p); /* non-auth answer as we can't fit the record */
  return 0;
}

int addrec_mx(struct dnspacket *p, 
              const unsigned char prio[2],
              const unsigned char *mxdn, unsigned mxdnlen) {
  register unsigned char *c = p->c;
  if (fit(p, c, 10 + 2 + 2)) {
    addrr_start(c, DNS_T_MX, &defttl_nbo); /* 10 bytes */
    c += 2;
    *c++ = prio[0]; *c++ = prio[1];
    if ((c = add_dn(p, c, mxdn, mxdnlen)) && fit(p, c, 2)) {
      mxdnlen = (c - p->c) - 12;
      p->c[10] = mxdnlen>>8; p->c[11] = mxdnlen;
      p->c = c;
      p->p[7] += 1;
      return 1;
    }
  }
  setnonauth(p->p); /* non-auth answer as we can't fit the record */
  return 0;
}

/* check whenever a given RR is already in the packet
 * (to suppress duplicate answers)
 * May be unnecessary? */
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

/* add a new record into answer, check for dups.
 * We just ignore any data that exceeds packet size */
int addrec_any(struct dnspacket *p, unsigned dtp,
               const void *data, unsigned dsz) {
  register unsigned char *c = p->c;
  if (aexists(p, dtp, data, dsz)) return 1;
  if (!fit(p, c, 12 + dsz)) {
    setnonauth(p->p); /* non-auth answer as we can't fit the record */
    return 0;
  }
  addrr_start(c, dtp, &defttl_nbo); /* 10 bytes */
  *c++ = dsz>>8; *c++ = dsz; /* dsize */
  memcpy(c, data, dsz);
  p->c = c + dsz;
  p->p[7] += 1; /* increment numanswers */
  return 1;
}

int
addrec_a(struct dnspacket *p, ip4addr_t aip) {
  unsigned char ip[4];
  ip[0] = aip >> 24; ip[1] = aip >> 16; ip[2] = aip >> 8; ip[3] = aip;
  return addrec_any(p, DNS_T_A, ip, 4);
}

int
addrec_txt(struct dnspacket *p, const char *txt, const char *subst) {
  unsigned sl;
  char sb[256];
  char *lp = sb + 1, *s, *const e = sb + 254;
  if (!txt) return 1;
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
    if (lp + sl > e) /* silently truncate TXT RR >255 bytes */
      sl = e - lp;
    memcpy(lp, subst, sl);
    lp += sl;
    txt = s + 1;
  }
  sl = lp - sb;
  sb[0] = sl - 1;
  return addrec_any(p, DNS_T_TXT, sb, sl);
}

static const char *
codename(unsigned c, const char *name, const char *base, char *buf)
{
  if (name) return name;
  sprintf(buf, "%s%d", base, c);
  return buf;
}

void logreply(const struct dnspacket *pkt, const char *ip,
              FILE *flog, int flushlog) {
  char cbuf[DNS_MAXDOMAIN + 200];
  char tbuf[20];
  char *cp = cbuf;
  const unsigned char *p;
  unsigned c;

  cp += sprintf(cp, "%lu %s ", (unsigned long)time(NULL), ip);
  p = pkt->p + 12;
  cp += dns_dntop(p, cp, DNS_MAXDOMAIN);
  p += dns_dnlen(p);
  c = ((unsigned)p[0]<<8)|p[1];
  cp += sprintf(cp, " %s ", codename(c, dns_typename(c), "type", tbuf));
  c = ((unsigned)p[2]<<8)|p[3];
  cp += sprintf(cp, "%s: ", codename(c, dns_classname(c), "class", tbuf));
  c = pkt->p[3];
  cp += sprintf(cp, "%s/%u/%d\n",
                codename(c, dns_rcodename(c), "rcode", tbuf),
                pkt->p[7], pkt->c - pkt->p);
  if (flushlog)
    write(fileno(flog), cbuf, cp - cbuf);
  else
    fwrite(cbuf, cp - cbuf, 1, flog);
}
