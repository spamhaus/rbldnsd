/* $Id$
 * DNS packet handling routines for rbldnsd
 */

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include "rbldnsd.h"

#ifndef NI_WITHSCOPEID
# define NI_WITHSCOPEID 0
#endif

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
           struct dnsquery *qry) {

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
    qry->q_lptr[qlab++] = d++;	/* another label */
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

const struct zone *
findqzone(const struct zone *zone,
          unsigned dnlen, unsigned dnlab, unsigned char *const *const dnlptr,
          struct dnsqueryinfo *qi) {
  const unsigned char *q;

  for(;; zone = zone->z_next) {
    if (!zone) return NULL;
    if (zone->z_dnlab > dnlab) continue;
    q = dnlptr[dnlab - zone->z_dnlab];
    if (memcmp(zone->z_dn, q, zone->z_dnlen - 1)) continue;
    break;
  }
  qi->qi_dn = dnlptr[0];
  qi->qi_dnlptr = dnlptr;
  qi->qi_dnlab = dnlab - zone->z_dnlab;
  qi->qi_dnlen0 = dnlen - zone->z_dnlen;
  if (zone->z_dstflags & DSTF_IP4REV) /* ip4 address */
    qi->qi_ip4valid = dntoip4addr(qi->qi_dn, qi->qi_dnlab, &qi->qi_ip4);

  return zone;
}

/* construct reply to a query. */
int replypacket(struct dnspacket *pkt, unsigned qlen, const struct zone *zone) {

  struct dnsquery qry;			/* query structure */
  struct dnsqueryinfo qi;		/* query info structure */
  unsigned char *const h = pkt->p_buf;	/* packet's header */
  const struct zonedatalist *zdl;
  int found;

  if (!(pkt->p_cur = pkt->p_sans = parsequery(h, qlen, &qry)))
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
  case DNS_T_ANY: qi.qi_tflag = NSQUERY_ANY; break;
  case DNS_T_A:   qi.qi_tflag = NSQUERY_A;   break;
  case DNS_T_TXT: qi.qi_tflag = NSQUERY_TXT; break;
  case DNS_T_NS:  qi.qi_tflag = NSQUERY_NS;  break;
  case DNS_T_SOA: qi.qi_tflag = NSQUERY_SOA; break;
  default:
    if (qry.q_type >= DNS_T_TSIG)
      return refuse(DNS_R_NOTIMPL);
    qi.qi_tflag = NSQUERY_OTHER;
  }
  h[p_f2] = DNS_R_NOERROR;

  /* find matching zone */
  zone = findqzone(zone, qry.q_dnlen, qry.q_dnlab, qry.q_lptr, &qi);
  if (!zone) /* not authoritative */
    return refuse(DNS_R_REFUSED);

  /* found matching zone */

  if (!zone->z_stamp)	/* do not answer if not loaded */
    return refuse(DNS_R_SERVFAIL);

  { /* initialize DN compression */
    struct dnsdnptr *ptr = pkt->p_dncompr.ptr;
    const unsigned char *dn = qry.q_dn;
    unsigned qpos = p_hdrsize;
    unsigned llen;
    qlen = qry.q_dnlen;
    while((llen = *dn)) {
      ptr->dnp = dn; dn += ++llen;
      ptr->dnlen = qlen; qlen -= llen;
      ptr->qpos = qpos; qpos += llen;
      ++ptr;
    }
    pkt->p_dncompr.cptr = ptr;
  }

  /* search the datasets */
  found = 0;
  for(zdl = zone->z_zdl; zdl; zdl = zdl->zdl_next)
    if (zdl->zdl_queryfn(zdl->zdl_zds, &qi, pkt))
      found = 1;	/* positive answer */

  if (qi.qi_dnlab == 0) {	/* query to base zone: SOA and NS only */

    found = 1;

    if (found && (qi.qi_tflag & NSQUERY_NS) && !addrr_ns(pkt, zone, 0))
      found = 0;
    if (found && (qi.qi_tflag & NSQUERY_SOA) && !addrr_soa(pkt, zone, 0))
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
      PACK16(c, dnlen);
      return c + 2;
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
    if ((c = add_dn(pkt, c, zsoa->zsoa_oldn+1, zsoa->zsoa_oldn[0])) &&
        (c = add_dn(pkt, c, zsoa->zsoa_pldn+1, zsoa->zsoa_pldn[0])) &&
        fit(pkt, c, 20)) {
      memcpy(c, &zsoa->zsoa_n, 20);
      c += 20;
      dsz = (c - rstart) - 2;
      PACK16(rstart, dsz);
      pkt->p_buf[auth ? p_nscnt : p_ancnt]++;
      pkt->p_cur = c;
      return 1;
    }
  }
  setnonauth(pkt->p_buf); /* non-auth answer as we can't fit the record */
  return 0;
}

static int addrr_ns(struct dnspacket *pkt, const struct zone *zone, int auth) {
  register unsigned char *c = pkt->p_cur;
  const unsigned char **nsp = zone->z_zttllns;
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
  if (zone->z_nns > 1) {	/* rotate nameservers */
    /* this is somewhat hackish: zone should not be modified here,
     * it's constant pointer for a reason.  But it's so easy to
     * spot errors elsewhere if an attempt will be made to modify
     * any data in this structure inside query handling routines...
     * After all, semantics (from nameserver point of view) does
     * not change.  But please keep this code in sync with zone
     * structure definition in rbldnsd.h */
    unsigned char **znsp = (unsigned char **)zone->z_zttllns;
    nsdn = znsp[0];
    memcpy(znsp, znsp + 1, (zone->z_nns - 1) * sizeof(*znsp));
    znsp[zone->z_nns - 1] = (unsigned char *)nsdn;
  }
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
      PACK16(pkt->p_cur + 10, mxdnlen);
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
  addrr_start(c, dtp, ttl);	/* 10 bytes */
  PACK16(c, dsz); c += 2;	/* dsize */
  memcpy(c, data, dsz);
  pkt->p_cur = c + dsz;
  pkt->p_buf[p_ancnt] += 1; /* increment numanswers */
}

/* implement substitutions.
 * `sb' is a buffer where the result will be stored -
 * at least 255 + 3 characters long */
static int
txtsubst(char *sb, const char *txt, const char *s0, char *const sn[10]) {
  unsigned sl;
  char *const e = sb + 254;
  char *lp = sb;
  const char *s, *si;
  if (!s0) s0 = "$";
  while(lp < e) {
    if ((s = strchr(txt, '$')) == NULL)
      s = (char*)txt + strlen(txt);
    sl = s - txt;
    if (lp + sl > e)
      sl = e - lp;
    memcpy(lp, txt, sl);
    lp += sl;
    if (!*s++) break;
    if (*s == '$') { si = s++; sl = 1; }
    else if (*s >= '0' && *s <= '9') { /* $1 var */
      si = sn[*s - '0'];
      if (!si) { si = s - 1; sl = 2; }
      else sl = strlen(si);
      ++s;
    }
    else
      sl = strlen(si = s0);
    if (lp + sl > e) /* silently truncate TXT RR >255 bytes */
      sl = e - lp;
    memcpy(lp, si, sl);
    lp += sl;
    txt = s;
  }
  sl = lp - sb;
  if (sl > 254) sl = 254;
  return sl;
}

void
addrr_a_txt(struct dnspacket *pkt, unsigned qtflag,
            const char *rr, const char *subst,
            const struct zonedataset *zds) {
  if (qtflag & NSQUERY_A)
    addrr_any(pkt, DNS_T_A, rr, 4, zds->zds_ttl);
  if (rr[4] && (qtflag & NSQUERY_TXT)) {
    char sb[260];
    unsigned sl = txtsubst(sb + 1, rr + 4, subst, zds->zds_subst);
    sb[0] = sl;
    addrr_any(pkt, DNS_T_TXT, sb, sl + 1, zds->zds_ttl);
  }
}

void
dump_a_txt(const char *name, const unsigned char *rr,
           const char *subst, const struct zonedataset *zds, FILE *f) {
  if (!rr)
    fprintf(f, "%s\tCNAME\texcluded\n", name);
  else {
    fprintf(f, "%s\tA\t%u.%u.%u.%u\n",
            name, rr[0], rr[1], rr[2], rr[3]);
    if (rr[4]) {
      char txt[260];
      char *p, *n;
      txt[txtsubst(txt, rr + 4, subst, zds->zds_subst)] = '\0';
      fprintf(f, "\tTXT\t\"");
      for(p = txt; (n = strchr(p, '"')) != NULL; p = n + 1) {
        fwrite(p, 1, n - p, f);
        putc('\\', f); putc('"', f);
      }
      fprintf(f, "%s\"\n", p);
    }
  }
}


void logreply(const struct dnspacket *pkt,
              const struct sockaddr *peeraddr, int peeraddrlen,
              FILE *flog, int flushlog) {
#ifndef NOIPv6
# ifndef NI_MAXHOST
#  define IPSIZE 1025
# else
#  define IPSIZE NI_MAXHOST
# endif
#else
# define IPSIZE 16
#endif
  char cbuf[DNS_MAXDOMAIN + IPSIZE + 50];
  char *cp = cbuf;
  const unsigned char *const q = pkt->p_sans - 4;

  cp += sprintf(cp, "%lu ", (unsigned long)time(NULL));
#ifndef NOIPv6
  if (getnameinfo(peeraddr, peeraddrlen,
                  cp, NI_MAXHOST, NULL, 0,
                  NI_NUMERICHOST|NI_WITHSCOPEID) == 0)
    cp += strlen(cp);
  else
    *cp++ = '?';
#else
  strcpy(cp, ip4atos(ntohl(((struct sockaddr_in*)peeraddr)->sin_addr.s_addr)));
  cp += strlen(cp);
#endif
  *cp++ = ' ';
  cp += dns_dntop(pkt->p_buf + p_hdrsize, cp, DNS_MAXDOMAIN);
  cp += sprintf(cp, " %s %s: %s/%u/%d\n",
      dns_typename(((unsigned)q[0]<<8)|q[1]),
      dns_classname(((unsigned)q[2]<<8)|q[3]),
      dns_rcodename(pkt->p_buf[p_f2] & pf2_rcode),
      pkt->p_buf[p_ancnt], pkt->p_cur - pkt->p_buf);
  if (flushlog)
    write(fileno(flog), cbuf, cp - cbuf);
  else
    fwrite(cbuf, cp - cbuf, 1, flog);
}
