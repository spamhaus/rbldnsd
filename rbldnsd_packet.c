/* $Id$
 * DNS packet handling routines for rbldnsd
 */

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "rbldnsd.h"

static int addrr_soa(struct dnspacket *pkt, const struct zone *zone, int auth);
static int addrr_ns(struct dnspacket *pkt, const struct zone *zone, int auth);

/* DNS packet:
 * bytes comment */
/* 0:1   identifier (client supplied) */
#define p_id1 0
#define p_id2 1
/* 2     flags1 */
#define p_f1 2
#define pf1_qr     0x80	/* query response flag */
#define pf1_opcode 0x78	/* opcode, 0 = query */
#define pf1_aa     0x04	/* auth answer */
#define pf1_tc     0x02	/* truncation flag */
#define pf1_rd     0x01	/* recursion desired (may be set in query) */
/* 3     flags2 */
#define p_f2 3
#define pf2_ra     0x80	/* recursion available */
#define pf2_z      0x70	/* reserved */
#define pf2_rcode  0x0f	/* response code */
  /* 0 ok, 1 format error, 2 servfail, 3 nxdomain, 4 notimpl, 5 refused */
/* 4:5   qdcount (numqueries) */
#define p_qdcnt1 4
#define p_qdcnt2 5
/* 6:7   ancount (numanswers) */
#define p_ancnt1 6
#define p_ancnt2 7
/* 8:9   nscount (numauthority) */
#define p_nscnt1 8
#define p_nscnt2 9
/* 10:11 arcount (numadditional) */
#define p_arcnt1 10
#define p_arcnt2 11
#define p_hdrsize 12	/* size of packet header */
/* next is a DN name, a series of labels with first byte is label's length,
 *  terminated by zero-length label (i.e. at least one zero byte is here)
 * next two bytes are query type (A, SOA etc)
 * next two bytes are query class (IN, HESIOD etc)
 */

/* since all counts are <255 due to size constraints, define
 * aliases for 2nd bytes */
#define p_qdcnt p_qdcnt2
#define p_ancnt p_ancnt2
#define p_nscnt p_nscnt2
#define p_arcnt p_arcnt2

/* parsequery: parse query packet
 * initializes q_dn, q_dnlen, q_dnlab, q_type, q_class
 * returns pointer after qDN (where answer section will begin)
 * or NULL on failure. */

static unsigned char *
parsequery(register const unsigned char *q, unsigned qlen,
           struct dnsquery *qry, unsigned char **lptr) {

  /* parsing incoming query.  Untrusted data read directly from the network.
   * q is a buffer ptr - data that was read (DNS_MAXPACKET max).
   * qlen is number of bytes actually read (packet length)
   * first p_hdrsize bytes is header, next is query DN,
   * next are QTYPE and QCLASS (2x2 bytes).
   * rest of data if any is ignored.
   */

  register unsigned const char *x, *e;
  register unsigned char *d;
  unsigned qlab;			/* number of labels in qDN */

  x = q + qlen - 5;	/* last possible qDN zero terminator position */
  /* qlen isn't needed anymore, it'll be used as length of qDN below */

  if (q + p_hdrsize > x)	/* short packet (header isn't here) */
    return NULL;
  else if (q + p_hdrsize + DNS_MAXDN <= x)
    x = q + p_hdrsize + DNS_MAXDN - 1; /* constrain query DN to DNS_MAXDN */

  if (q[p_f1] & pf1_qr)			/* response packet?! */
     return 0;
  if (q[p_qdcnt1] || q[p_qdcnt2] != 1)	/* qdcount should be == 1 */
    return NULL;

  /* parse and lowercase query DN, count and init labels */
  qlab = 0;			/* number of labels so far */
  q += p_hdrsize;		/* start of qDN */
  d = qry->q_dn;		/* destination lowercased DN */
  while((*d = *q) != 0) {	/* loop by DN lables */
    lptr[qlab++] = d++;		/* another label */
    e = q + *q + 1;		/* end of this label */
    if (*q > DNS_MAXLABEL	/* too long label? */
        || e > x)		/* or it ends past packet? */
      return NULL;
    /* lowercase it */
    ++q;			/* length */
    do *d++ = dns_dnlc(*q);	/* lowercase each char */
    while(++q < e);		/* until end of label */
  }
  /* d points to qDN terminator now */
  qry->q_dnlen = d - qry->q_dn + 1;
  qry->q_dnlab = qlab;

  /* q is end of qDN. decode qtype and qclass, and prepare for an answer */
  ++q;
  qry->q_type = ((unsigned)(q[0]) << 8) | q[1];
  qry->q_class = ((unsigned)(q[2]) << 8) | q[3];

  return (unsigned char*)q + 4;	/* answers will start here */
}

/* construct reply to a query. */
int replypacket(struct dnspacket *pkt, unsigned qlen, const struct zone *zone) {

  struct dnsquery qry;			/* query structure */
  unsigned char *const h = pkt->p_buf;	/* packet's header */
  unsigned qlab;
  unsigned char *lptr[DNS_MAXLABELS];
  const struct zonedatalist *zdl;
  int found;

  if (!(pkt->p_cur = pkt->p_sans = parsequery(h, qlen, &qry, lptr)))
    return 0;

  /* from now on, we see (almost?) valid dns query, should reply */

#define setnonauth(h) (h[p_f1] &= ~pf1_aa)
#define refuse(code) (setnonauth(h), h[p_f2] = (code), pkt->p_sans - h)

  /* construct reply packet */

  /* identifier already in place */
  /* flags will be set up later */
  /* qdcount already set up in query */
  /* all counts (qd,an,ns,ar) are <= 255 due to size limit */
  h[p_ancnt1] = h[p_ancnt2] = 0;
  h[p_nscnt1] = h[p_nscnt2] = 0;
  h[p_arcnt1] = h[p_arcnt2] = 0;

  if (h[p_f1] & (pf1_opcode | pf1_aa | pf1_tc | pf1_qr))
    return h[p_f1] = pf1_qr, refuse(DNS_R_NOTIMPL);
  h[p_f1] |= pf1_qr;
  if (qry.q_class == DNS_C_IN)
    h[p_f1] |= pf1_aa;
  else if (qry.q_class != DNS_C_ANY)
    return refuse(DNS_R_FORMERR);
  switch(qry.q_type) {
  case DNS_T_ANY: qry.q_tflag = NSQUERY_ANY; break;
  case DNS_T_A:   qry.q_tflag = NSQUERY_A;   break;
  case DNS_T_TXT: qry.q_tflag = NSQUERY_TXT; break;
  case DNS_T_NS:  qry.q_tflag = NSQUERY_NS;  break;
  case DNS_T_SOA: qry.q_tflag = NSQUERY_SOA; break;
  default:
    if (qry.q_type >= DNS_T_TSIG)
      return refuse(DNS_R_NOTIMPL);
    qry.q_tflag = NSQUERY_OTHER;
  }
  h[p_f2] = DNS_R_NOERROR;

  /* find matching zone */
  qlab = qry.q_dnlab;
  qlen = qry.q_dnlen;
  for(;; zone = zone->z_next) {
    unsigned char *q;
    if (!zone) /* not authoritative */
      return refuse(DNS_R_REFUSED);
    if (zone->z_dnlab > qlab) continue;
    q = lptr[qlab - zone->z_dnlab];
    if (zone->z_dnlen != qlen - (q - qry.q_dn)) continue;
    if (memcmp(zone->z_dn, q, zone->z_dnlen)) continue;
    *q = '\0'; /* terminate at base zone */
    break;
  }

  /* found matching zone */
  if (!zone->z_stamp)	/* do not answer if not loaded */
    return refuse(DNS_R_SERVFAIL);

  /* initialize query */
  qry.q_dnlen = (qlen -= zone->z_dnlen - 1);
  qry.q_dnlab -= zone->z_dnlab;

  { /* initialize DN compression */
    /* start at zone DN, not at query DN, as qDN may contain
     * unnecessary long DN.  Zone DN should fit in dncompr array */
    struct dnsdnptr *ptr = pkt->p_dncompr.ptr;
    const unsigned char *dn = zone->z_dn;
    unsigned qpos = (pkt->p_sans - h) - 4 - qlen;
    unsigned llen;
    while((llen = *dn)) {
      ptr->dnp = dn; dn += ++llen;
      ptr->dnlen = qlen; qlen -= llen;
      ptr->qpos = qpos; qpos += llen;
      ++ptr;
    }
    pkt->p_dncompr.cptr = ptr;
  }

  /* initialize various query variations */
  if (zone->z_dstflags & DSTF_IP4REV) /* ip4 address */
    qry.q_ip4oct = qry.q_dnlab <= 4 ? dntoip4addr(qry.q_dn, &qry.q_ip4) : 0;
  if (zone->z_dstflags & DSTF_DNREV)	/* reverse DN */
    dns_dnreverse(qry.q_dn, qry.q_rdn, qry.q_dnlen);

  /* search the datasets */
  found = 0;
  for(zdl = zone->z_zdl; zdl; zdl = zdl->zdl_next)
    if (zdl->zdl_queryfn(zdl->zdl_zds, &qry, pkt))
      found = 1;	/* positive answer */

  if (qry.q_dnlab == 0) {	/* query to base zone: SOA and NS only */

    found = 1;

    if (found && (qry.q_tflag & NSQUERY_NS) && !addrr_ns(pkt, zone, 0))
      found = 0;
    if (found && (qry.q_tflag & NSQUERY_SOA) && !addrr_soa(pkt, zone, 0))
      found = 0;
    if (!found) {
      pkt->p_cur = pkt->p_sans;
      h[p_ancnt] = h[p_nscnt] = 0;
      return refuse(DNS_R_REFUSED);
    }

  }

  if (!found) {			/* negative result */
    addrr_soa(pkt, zone, 1);	/* add SOA if any to AUTHORITY */
    h[p_f2] = DNS_R_NXDOMAIN;
  }
  else if (!h[p_ancnt]) {	/* positive reply, no answers */
    addrr_soa(pkt, zone, 1);	/* add SOA if any to AUTHORITY */
  }

  return pkt->p_cur - h;

}

#define fit(p, c, bytes) ((c) + (bytes) <= (p)->p_buf + DNS_MAXPACKET)

/* adds 8 bytes */
#define addrr_rrstart(c,type,ttl)		\
    *(c)++ = type>>8; *(c)++ = type;		\
    *(c)++ = DNS_C_IN>>8; *(c)++ = DNS_C_IN;	\
    memcpy((c), ttl, 4); (c) += 4

/* adds 10 bytes */
#define addrr_start(c,type,ttl)						\
    *(c)++ = 192; *(c)++ = p_hdrsize; /* jump after header: query DN */	\
    addrr_rrstart((c),type,ttl)

static unsigned char *
add_dn(struct dnspacket *pkt, register unsigned char *c,
       const unsigned char *dn, unsigned dnlen) {
  struct dnsdnptr *ptr;
  struct dnsdncompr *compr = &pkt->p_dncompr;

  while(*dn) {
    for(ptr = compr->ptr; ptr < compr->cptr; ++ptr) {
      if (ptr->dnlen != dnlen || memcmp(ptr->dnp, dn, dnlen) != 0)
        continue;
      if (!fit(pkt, c, 2)) return NULL;
      dnlen = 0xc000 + ptr->qpos;
      *c++ = dnlen >> 8; *c++ = dnlen;
      return c;
    }
    if (!fit(pkt, c, *dn + 1))
      return NULL;
    if (ptr < compr->ptr + DNS_MAXLABELS) {
      ptr->dnp = dn;
      ptr->dnlen = dnlen;
      ptr->qpos = c - pkt->p_buf;
      ++compr->cptr;
    }
    memcpy(c, dn, *dn + 1);
    c += *dn + 1;
    dnlen -= *dn + 1;
    dn += *dn + 1;
  }
  if (!fit(pkt, c, 1)) return NULL;
  *c++ = '\0';
  return c;
}

static int addrr_soa(struct dnspacket *pkt, const struct zone *zone, int auth) {
  register unsigned char *c;
  unsigned char *rstart;
  unsigned dsz;
  const struct zonesoa *zsoa = &zone->z_zsoa;
  if (!zsoa->zsoa_valid) {
    if (!auth)
      setnonauth(pkt->p_buf); /* non-auth answer as we can't fit the record */
    return 0;
  }
  c = pkt->p_cur;
  /* since SOA always comes last, no need to save dncompr state */
  if ((c = add_dn(pkt, c, zone->z_dn, zone->z_dnlen)) && fit(pkt, c, 8 + 2)) {
    /* 8 bytes */
    addrr_rrstart(c, DNS_T_SOA, auth ? zsoa->zsoa_n + 16 : zsoa->zsoa_ttl);
    rstart = c;
    c += 2;
    if ((c = add_dn(pkt, c, zsoa->zsoa_odn+1, zsoa->zsoa_odn[0])) &&
        (c = add_dn(pkt, c, zsoa->zsoa_pdn+1, zsoa->zsoa_pdn[0])) &&
        fit(pkt, c, 20)) {
      memcpy(c, &zsoa->zsoa_n, 20);
      c += 20;
      dsz = (c - rstart) - 2;
      rstart[0] = dsz >> 8; rstart[1] = dsz;
      pkt->p_buf[auth ? p_arcnt : p_ancnt]++;
      pkt->p_cur = c;
      return 1;
    }
  }
  setnonauth(pkt->p_buf); /* non-auth answer as we can't fit the record */
  return 0;
}

static int addrr_ns(struct dnspacket *pkt, const struct zone *zone, int auth) {
  register unsigned char *c = pkt->p_cur;
  const unsigned char **nsp = zone->z_zns;
  const unsigned char **nse = nsp + zone->z_nns;
  const unsigned char *nsdn;
  if (nsp == nse) return 0;
  do {
    if (fit(pkt, c, 10 + 2)) {
      nsdn = *nsp;
      addrr_start(c, DNS_T_NS, nsdn); /* 10 bytes */
      c[0] = 0;
      if ((c = add_dn(pkt, c + 2, nsdn + 5, nsdn[4]))) {
        pkt->p_cur[11] = c - pkt->p_cur - 12;
        pkt->p_cur = c;
        pkt->p_buf[auth ? p_nscnt : p_ancnt] += 1;
        continue;
      }
    }
    setnonauth(pkt->p_buf); /* non-auth answer as we can't fit the record */
    return 0;
  } while(++nsp < nse);
  return 1;
}

void addrr_mx(struct dnspacket *pkt,
              const unsigned char pri[2],
              const unsigned char *mxdn, unsigned mxdnlen,
              const unsigned char ttl[4]) {
  register unsigned char *c = pkt->p_cur;
  if (fit(pkt, c, 10 + 2 + 2)) {
    addrr_start(c, DNS_T_MX, ttl);
    c += 2;
    *c++ = pri[0]; *c++ = pri[1];
    if ((c = add_dn(pkt, c, mxdn, mxdnlen))) {
      mxdnlen = c - pkt->p_cur - 12;
      pkt->p_cur[10] = mxdnlen>>8; pkt->p_cur[11] = mxdnlen;
      pkt->p_cur = c;
      pkt->p_buf[p_ancnt] += 1;
      return;
    }
  }
  setnonauth(pkt->p_buf);
}

/* check whenever a given RR is already in the packet
 * (to suppress duplicate answers)
 * May be unnecessary? */
static int aexists(const struct dnspacket *pkt, unsigned typ,
                   const void *val, unsigned vlen) {
  const unsigned char *c, *e;
  for(c = pkt->p_sans, e = pkt->p_cur; c < e; c = c + 12 + c[11]) {
    if (c[2] == (typ>>8) && c[3] == (typ&255) &&
        c[11] == vlen && memcmp(c + 12, val, vlen) == 0)
      return 1;
  }
  return 0;
}

/* add a new record into answer, check for dups.
 * We just ignore any data that exceeds packet size */
void addrr_any(struct dnspacket *pkt, unsigned dtp,
               const void *data, unsigned dsz,
               const unsigned char ttl[4]) {
  register unsigned char *c = pkt->p_cur;
  if (aexists(pkt, dtp, data, dsz)) return;
  if (!fit(pkt, c, 12 + dsz)) {
    setnonauth(pkt->p_buf); /* non-auth answer as we can't fit the record */
    return;
  }
  addrr_start(c, dtp, ttl); /* 10 bytes */
  *c++ = dsz>>8; *c++ = dsz; /* dsize */
  memcpy(c, data, dsz);
  pkt->p_cur = c + dsz;
  pkt->p_buf[p_ancnt] += 1; /* increment numanswers */
}

void
addrr_a_txt(struct dnspacket *pkt, unsigned qtflag,
            const char *rr, const char *subst,
            const struct zonedataset *zds) {
  if (qtflag & NSQUERY_A)
    addrr_any(pkt, DNS_T_A, rr, 4, zds->zds_ttl);
  if (*(rr += 4) && (qtflag & NSQUERY_TXT)) {
    unsigned sl;
    char sb[258];
    char *const e = sb + 254;
    char *lp = sb + 1;
    const char *s, *si;
    if (!subst) subst = "$";
    while(lp < e) {
      if ((s = strchr(rr, '$')) == NULL)
        s = (char*)rr + strlen(rr);
      sl = s - rr;
      if (lp + sl > e)
        sl = e - lp;
      memcpy(lp, rr, sl);
      lp += sl;
      if (!*s++) break;
      if (*s == '$') { si = s++; sl = 1; }
      else if (*s >= '0' && *s <= '9') { /* $1 var */
        si = zds->zds_subst[*s - '0'];
        if (!si) { si = s - 1; sl = 2; }
        else sl = strlen(si);
        ++s;
      }
      else
        sl = strlen(si = subst);
      if (lp + sl > e) /* silently truncate TXT RR >255 bytes */
        sl = e - lp;
      memcpy(lp, si, sl);
      lp += sl;
      rr = s;
    }
    sl = lp - sb;
    if (sl > 254) sl = 254;
    sb[0] = sl - 1;
    addrr_any(pkt, DNS_T_TXT, sb, sl, zds->zds_ttl);
  }
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
  const unsigned char *const h = pkt->p_buf;
  const unsigned char *const q = pkt->p_sans - 4;
  unsigned c;

  cp += sprintf(cp, "%lu %s ", (unsigned long)time(NULL), ip);
  cp += dns_dntop(h + p_hdrsize, cp, DNS_MAXDOMAIN);
  c = ((unsigned)q[0]<<8)|q[1];
  cp += sprintf(cp, " %s ", codename(c, dns_typename(c), "type", tbuf));
  c = ((unsigned)q[2]<<8)|q[3];
  cp += sprintf(cp, "%s: ", codename(c, dns_classname(c), "class", tbuf));
  c = h[3];
  cp += sprintf(cp, "%s/%u/%d\n",
                codename(c, dns_rcodename(c), "rcode", tbuf),
                h[p_ancnt], pkt->p_cur - pkt->p_buf);
  if (flushlog)
    write(fileno(flog), cbuf, cp - cbuf);
  else
    fwrite(cbuf, cp - cbuf, 1, flog);
}
