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

#ifdef RECOGNIZE_IP4IN6
static const unsigned char *const ip6p =
  "\001f\001f\001f\001f\0010\0010\0010\0010"
  "\0010\0010\0010\0010\0010\0010\0010\0010"
  "\0010\0010\0010\0010\0010\0010\0010\0010"
  "\003ip6";
#endif

/* parse DN (as in 4.3.2.1.in-addr.arpa) to ip4addr_t */
static int dntoip4addr(const unsigned char *q, unsigned qlen0, unsigned qlab,
                       ip4addr_t *ap) {
  ip4addr_t a = 0, o;
  if (qlab != 4) {

#ifdef RECOGNIZE_IP4IN6

     if ((qlab != 33 || qlen0 != 68 || memcmp(q + 16, ip6p, 28) != 0) &&
         (qlab != 32 || qlen0 != 64 || memcmp(q + 16, ip6p, 24) != 0))
       return 0;
     for (o = 0; o < 32; o += 4) {
       ++q;
       if (*q >= '0' && *q <= '9')
         a |= (unsigned)(*q++ - '0') << o;
       else if (*q >= 'a' && *q <= 'f')
         a |= (unsigned)(*q++ - 'a' + 10) << o;
       else
         return 0;
     }
     *ap = a;
     return 1;

#else /* RECOGNIZE_IP4IN6 */
     return 0;
#endif

  }

#define digit(c) ((c) >= '0' && (c) <= '9')
#define d2n(c) ((unsigned)((c) - '0'))

#define oct(q,o)					\
    switch(*q) {					\
    case 1:						\
      if (!digit(q[1]))					\
        return 0;					\
      o = d2n(q[1]);					\
      break;						\
    case 2:						\
      if (!digit(q[1]) || !digit(q[2]))			\
        return 0;					\
      o = d2n(q[1]) * 10 + d2n(q[2]);			\
      break;						\
    case 3:						\
      if (!digit(q[1]) || !digit(q[2]) || !digit(q[3]))	\
        return 0;					\
      o = d2n(q[1]) * 100 + d2n(q[2]) * 10 + d2n(q[3]);	\
      if (o > 255) return 0;				\
      break;						\
    default: return 0;					\
    }
  oct(q,o); a |= o;  q += *q + 1;
  oct(q,o); a |= o << 8;  q += *q + 1;
  oct(q,o); a |= o << 16;  q += *q + 1;
  oct(q,o); a |= o << 24;
  *ap = a;
  return 1;
#undef oct
#undef digit
#undef d2n
}

const struct zone *
findqzone(const struct zone *zone,
          unsigned dnlen, unsigned dnlab, unsigned char *const *const dnlptr,
          struct dnsqinfo *qi) {
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
    qi->qi_ip4valid =
      dntoip4addr(qi->qi_dn, qi->qi_dnlen0, qi->qi_dnlab, &qi->qi_ip4);

  return zone;
}

/* construct reply to a query. */
int replypacket(struct dnspacket *pkt, unsigned qlen, const struct zone *zone) {

  struct dnsquery qry;			/* query structure */
  struct dnsqinfo qi;			/* query info structure */
  unsigned char *const h = pkt->p_buf;	/* packet's header */
  const struct dslist *dsl;
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
  case DNS_T_MX:  qi.qi_tflag = NSQUERY_MX;  break;
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

  if (qi.qi_dnlab == 0) {	/* query to base zone: SOA and NS */

    found = 1;

    if ((qi.qi_tflag & NSQUERY_SOA) && !addrr_soa(pkt, zone, 0))
      found = 0;
    else
    if ((qi.qi_tflag & NSQUERY_NS) && !addrr_ns(pkt, zone, 0))
      found = 0;
    if (!found) {
      pkt->p_cur = pkt->p_sans;
      h[p_ancnt] = h[p_nscnt] = 0;
      return refuse(DNS_R_REFUSED);
    }

  }
  else /* not to zone base DN */
    found = 0;

  /* search the datasets */
  for(dsl = zone->z_dsl; dsl; dsl = dsl->dsl_next)
    if (dsl->dsl_queryfn(dsl->dsl_ds, &qi, pkt))
      found = 1;	/* positive answer */

  /* now complete the reply: add AUTH etc sections */
  if (!found) {			/* negative result */
    addrr_soa(pkt, zone, 1);	/* add SOA if any to AUTHORITY */
    h[p_f2] = DNS_R_NXDOMAIN;
  }
  else if (!h[p_ancnt]) {	/* positive reply, no answers */
    addrr_soa(pkt, zone, 1);	/* add SOA if any to AUTHORITY */
  }
  else if (zone->z_nns && (!(qi.qi_tflag & NSQUERY_NS) || qi.qi_dnlab))
    addrr_ns(pkt, zone, 1); /* add nameserver records to positive reply */

  return pkt->p_cur - h;

}

#define fit(p, c, bytes) ((c) + (bytes) <= (p)->p_buf + DNS_MAXPACKET)


/* DN compression pointers/structures */

/* We store pre-computed RRs for NS and SOA records in special
 * cache buffers referenced to by zone structure.
 *
 * The precomputed RRs consists of ready-to-be-sent data (with
 * all record types/classes, TTLs, and data in place), modulo
 * compressed DN backreferences.  When this cached data will be
 * copied into answer packet, we'll need to adjust "jumps" in
 * DN name compressions to reflect actual position of the data
 * in answer packet.
 *
 * Cache data is calculated as if it where inside some packet,
 * where it's start is exactly at the beginning of cached/precomputed
 * record, and with zone's base DN (with class and type) being in
 * question section immediately BEFORE the data (i.e. before our
 * "virtual packet").  So some DN compression offsets (pointers)
 * will be negative (referring to the query section of actual answer,
 * as zone base DN will be present in answer anyway), and some will
 * be positive (referring to this very record in actual answer).
 */

struct dnjump {	/* one DN "jump": */
  unsigned char *pos;	/* position in precomputed packet where the jump is */
  int off;		/* jump offset relative to beginning of the RRs */
};

struct dnptr {	/* domain pointer for DN compression */
  const unsigned char *dn;	/* actual (complete) domain name */
  int off;			/* jump offset relative to start of RRs */
};

struct dncompr {	/* DN compression structure */
  struct dnptr ptr[256];	/* array of all known domain names */
  struct dnptr *lptr;		/* last unused slot in ptr[] */
  unsigned char *buf;		/* buffer for the cached RRs */
  unsigned char *bend;		/* pointer to past the end of buf */
  struct dnjump *jump;		/* current jump ptr (array of jumps) */
};

#define CACHEBUF_SIZE (DNS_MAXPACKET-p_hdrsize-4)
/* maxpacket minus header minus (class+type) */

/* initialize compression/cache structures */
static unsigned char *
dnc_init(struct dncompr *compr,
         unsigned char *buf, unsigned bufsize, struct dnjump *jump,
         const unsigned char *dn) {
  struct dnptr *ptr;
  unsigned char *cpos;

  compr->buf = buf; compr->bend = buf + bufsize;
  compr->jump = jump;

  cpos = buf - dns_dnlen(dn) - 4; /* current position: qDN BEFORE the RRs */
  ptr = compr->ptr;

  while(*dn) {
    ptr->dn = dn;
    ptr->off = cpos - buf;
    ++ptr;
    cpos += *dn + 1;
    dn += *dn + 1;
  }
  compr->lptr = ptr;
  return cpos + 5;
}

/* add one DN into cache, adjust compression pointers and current pointer */
static unsigned char *
dnc_add(struct dncompr *compr, unsigned char *cpos, const unsigned char *dn) {
  struct dnptr *ptr;

  while(*dn) {
    /* lookup DN in already stored names */
    for(ptr = compr->ptr; ptr < compr->lptr; ++ptr) {
      if (!dns_dnequ(ptr->dn, dn))
        continue;
      /* found one, make a jump to it */
      if (cpos + 2 >= compr->bend) return NULL;
      compr->jump->pos = cpos;
      compr->jump->off = ptr->off;
      ++compr->jump;
      return cpos + 2;
    }
    /* not found, add it to the list of known DNs... */
    if (cpos + *dn + 1 >= compr->bend)
      return NULL;	/* does not fit */
    if (ptr < compr->ptr + sizeof(compr->ptr) / sizeof(compr->ptr[0])) {
      ptr->dn = dn;
      ptr->off = cpos - compr->buf;
      ++compr->lptr;
    }
    /* ...and add one label into the "packet" */
    memcpy(cpos, dn, *dn + 1);
    cpos += *dn + 1;
    dn += *dn + 1;
  }
  if (cpos + 1 >= compr->bend)
    return NULL;
  *cpos++ = '\0';
  return cpos;
}

/* finalize RRs: remember it's size and number of jumps */
static void dnc_finish(struct dncompr *compr, unsigned char *cptr,
                       unsigned *sizep, struct dnjump **jendp) {
   *sizep = cptr - compr->buf;
   *jendp = compr->jump;
}

/* place pre-cached RRs into the packet, adjusting jumps */
static int
dnc_final(struct dnspacket *pkt,
          const unsigned char *data, unsigned dsize,
          const struct dnjump *jump,
          const struct dnjump *jend) {
  const unsigned qoff = (pkt->p_sans - pkt->p_buf) + 0xc000;
  const unsigned coff = (pkt->p_cur - pkt->p_buf) + 0xc000;
  unsigned pos;
  if (!fit(pkt, pkt->p_cur, dsize))
    return 0;
  /* first, adjust offsets - in cached data anyway */
  while(jump < jend) {
    /* jump to either query section or this very RRs */
    pos = jump->off + (jump->off < 0 ? qoff : coff);
    PACK16(jump->pos, pos);
    ++jump;
  }
  /* and finally, copy the RRs into answer packet */
  memcpy(pkt->p_cur, data, dsize);
  pkt->p_cur += dsize;
  return 1;
}


struct zonesoa {	/* cached SOA RR */
  unsigned size;		/* size of the RR */
  unsigned ttloff;		/* offset of the TTL field */
  const unsigned char *minttl;	/* pointer to minttl in data */
  struct dnjump jump[3];	/* jumps to fix: 3 max (qdn, odn, pdn) */
  struct dnjump *jend;		/* last jump */
  unsigned char data[CACHEBUF_SIZE];
};

struct zonens {		/* cached NS RRs */
  unsigned size;		/* total size of all NS RRs */
  struct dnjump jump[MAX_NS*2];	/* jumps: for qDNs and for NSes */
  struct dnjump *jend;		/* last jump */
  unsigned char data[CACHEBUF_SIZE];
};

void init_zone_caches(struct zone *zone) {
  zone->z_zsoa = tmalloc(struct zonesoa);
  /* for NS RRs, we allocate MAX_NS caches:
   * each stores one variant of NS rotation */
  zone->z_zns = (struct zonens *)emalloc(sizeof(struct zonens) * MAX_NS);
}

/* update SOA RR cache */

int update_zone_soa(struct zone *zone, const struct dssoa *dssoa) {
   struct zonesoa *zsoa;
   unsigned char *cpos;
   struct dncompr compr;
   unsigned size;
   unsigned char *sizep;

   zsoa = zone->z_zsoa;
   zsoa->size = 0;
   if (!(zone->z_dssoa = dssoa)) return 1;

   cpos = dnc_init(&compr, zsoa->data, sizeof(zsoa->data),
                   zsoa->jump, zone->z_dn);

   cpos = dnc_add(&compr, cpos, zone->z_dn);
   *cpos++ = DNS_T_SOA>>8; *cpos++ = DNS_T_SOA;
   *cpos++ = DNS_C_IN >>8; *cpos++ = DNS_C_IN;
   zsoa->ttloff = cpos - compr.buf;
   memcpy(cpos, dssoa->dssoa_ttl, 4); cpos += 4;
   sizep = cpos;
   cpos += 2;
   cpos = dnc_add(&compr, cpos, dssoa->dssoa_odn);
   if (!cpos) return 0;
   cpos = dnc_add(&compr, cpos, dssoa->dssoa_pdn);
   if (!cpos) return 0;
   if (dssoa->dssoa_serial)
     PACK32(cpos, dssoa->dssoa_serial);
   else
     PACK32(cpos, zone->z_stamp);
   cpos += 4;
   memcpy(cpos, dssoa->dssoa_n, 16); cpos += 16;
   zsoa->minttl = cpos - 4;
   size = cpos - sizep - 2;
   PACK16(sizep, size);
   dnc_finish(&compr, cpos, &zsoa->size, &zsoa->jend);

   return 1;
}

static int addrr_soa(struct dnspacket *pkt, const struct zone *zone, int auth) {
  const struct zonesoa *zsoa = zone->z_zsoa;
  unsigned char *c = pkt->p_cur;
  if (!zone->z_dssoa || !zsoa->size) {
    if (!auth)
      setnonauth(pkt->p_buf);
    return 0;
  }
  if (!dnc_final(pkt, zsoa->data, zsoa->size, zsoa->jump, zsoa->jend)) {
    if (!auth)
      setnonauth(pkt->p_buf); /* non-auth answer as we can't fit the record */
    return 0;
  }
  /* for AUTHORITY section for NXDOMAIN etc replies, use minttl as TTL */
  if (auth) memcpy(c + zsoa->ttloff, zsoa->minttl, 4);
  pkt->p_buf[auth ? p_nscnt : p_ancnt]++;
  return 1;
}

int update_zone_ns(struct zone *zone, const struct dsns **dsnsa, unsigned nns) {
  struct zonens *zns;
  unsigned char *cpos, *sizep;
  struct dncompr compr;
  unsigned size, i, ns;
  const struct dsns *dsns;

  zone->z_nns = 0;
  zns = zone->z_zns;
  if (!nns)
    return 1;
  memcpy(zone->z_dsnsa, dsnsa, sizeof(zone->z_dsnsa));

  /* fill up nns variants of NS RRs ordering:
   * zns is actually an array, not single structure */
  ns = 0;
  for(;;) {
    cpos = dnc_init(&compr, zns->data, sizeof(zns->data),
                    zns->jump, zone->z_dn);

    for(i = 0; i < nns; ++i) {
      cpos = dnc_add(&compr, cpos, zone->z_dn);
      if (!cpos || cpos + 10 > compr.bend) return 0;
      *cpos++ = DNS_T_NS>>8; *cpos++ = DNS_T_NS;
      *cpos++ = DNS_C_IN>>8; *cpos++ = DNS_C_IN;
      memcpy(cpos, dsnsa[i]->dsns_ttl, 4); cpos += 4;
      sizep = cpos; cpos += 2;
      cpos = dnc_add(&compr, cpos, dsnsa[i]->dsns_dn);
      if (!cpos) return 0;
      size = cpos - sizep - 2;
      PACK16(sizep, size);
    }

    dnc_finish(&compr, cpos, &zns->size, &zns->jend);

    if (++ns >= nns) break;

    dsns = dsnsa[0];
    memcpy(dsnsa, dsnsa + 1, (nns - 1) * sizeof(*dsnsa));
    dsnsa[nns - 1] = dsns;
    ++zns;

  }
  zone->z_nns = nns;

  return 1;
}

static int addrr_ns(struct dnspacket *pkt, const struct zone *zone, int auth) {
  unsigned cns = zone->z_cns;
  const struct zonens *zns = zone->z_zns + cns;
  if (!zone->z_nns)
    return 0;
  if (!dnc_final(pkt, zns->data, zns->size, zns->jump, zns->jend))
    return 0;
  pkt->p_buf[auth ? p_nscnt : p_ancnt] += zone->z_nns;
  /* pick up next variation of NS ordering */
  ++cns;
  if (cns >= zone->z_nns)
    cns = 0;
  ((struct zone *)zone)->z_cns = cns;
  return 1;
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
  *c++ = 192; *c++ = p_hdrsize;	/* jump after header: query DN */
  *c++ = dtp>>8; *c++ = dtp;
  *c++ = DNS_C_IN>>8; *c++ = DNS_C_IN;
  memcpy(c, ttl, 4); c += 4;
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
            const struct dataset *ds) {
  if (qtflag & NSQUERY_A)
    addrr_any(pkt, DNS_T_A, rr, 4, ds->ds_ttl);
  if (rr[4] && (qtflag & NSQUERY_TXT)) {
    char sb[260];
    unsigned sl = txtsubst(sb + 1, rr + 4, subst, ds->ds_subst);
    sb[0] = sl;
    addrr_any(pkt, DNS_T_TXT, sb, sl + 1, ds->ds_ttl);
  }
}

void
dump_a_txt(const char *name, const unsigned char *rr,
           const char *subst, const struct dataset *ds, FILE *f) {
  if (!rr)
    fprintf(f, "%s\tCNAME\texcluded\n", name);
  else {
    fprintf(f, "%s\tA\t%u.%u.%u.%u\n",
            name, rr[0], rr[1], rr[2], rr[3]);
    if (rr[4]) {
      char txt[260];
      char *p, *n;
      txt[txtsubst(txt, rr + 4, subst, ds->ds_subst)] = '\0';
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
