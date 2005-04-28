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
#include <syslog.h>
#include "rbldnsd.h"
#include "rbldnsd_hooks.h"

#ifndef NOIPv6
# ifndef NI_MAXHOST
#  define IPSIZE 1025
# else
#  define IPSIZE NI_MAXHOST
# endif
#else
# define IPSIZE 16
#endif

#define MAX_GLUE (MAX_NS*2)

static int addrr_soa(struct dnspacket *pkt, const struct zone *zone, int auth);
static int addrr_ns(struct dnspacket *pkt, const struct zone *zone, int auth);
static int version_req(struct dnspacket *pkt, const struct dnsquery *qry);

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

static int
parsequery(struct dnspacket *pkt, unsigned qlen,
           struct dnsquery *qry) {

  /* parsing incoming query.  Untrusted data read directly from the network.
   * pkt->p_buf is a buffer - data that was read (DNS_EDNS0_MAXPACKET max).
   * qlen is number of bytes actually read (packet length)
   * first p_hdrsize bytes is header, next is query DN,
   * next are QTYPE and QCLASS (2x2 bytes).
   * If NSCNT==0 && ARCNT==1, and an OPT record comes after the query,
   * EDNS0 packet size gets extracted from the OPT record.
   * Rest of data is ignored.
   * Returns true on success, 0 on failure.
   * Upon successeful return, pkt->p_sans = pkt->p_cur points to the end of
   * the query section (where our answers will be placed), and
   * pkt->p_endp is initialized to point to the real end of answers.
   * Real end of answers is:
   * for non-EDNS0-aware clients it's pkt->p_buf+DNS_MAXPACKET, and
   * if a vaild EDNS0 UDPsize is given, it will be pkt->p_buf+UDPsize-11,
   * with the 11 bytes needed for a minimal OPT record.
   * In replypacket() we check whenever all our answers fits in standard
   * UDP buffer size (DNS_MAXPACKET), and if not (which means we're replying
   * to EDNS0-aware client due to the above rules), we just add proper OPT
   * record at the end.
   */

  register unsigned const char *q = pkt->p_buf;
  register unsigned const char *x, *e;
  register unsigned char *d;
  unsigned qlab;			/* number of labels in qDN */

  x = q + qlen - 5;	/* last possible qDN zero terminator position */
  /* qlen isn't needed anymore, it'll be used as length of qDN below */

  if (q + p_hdrsize > x)	/* short packet (header isn't here) */
    return 0;
  else if (q + p_hdrsize + DNS_MAXDN <= x)
    x = q + p_hdrsize + DNS_MAXDN - 1; /* constrain query DN to DNS_MAXDN */

  if (q[p_f1] & pf1_qr)			/* response packet?! */
    return 0;
  if (q[p_qdcnt1] || q[p_qdcnt2] != 1)	/* qdcount should be == 1 */
    return 0;

  /* parse and lowercase query DN, count and init labels */
  qlab = 0;			/* number of labels so far */
  q += p_hdrsize;		/* start of qDN */
  d = qry->q_dn;		/* destination lowercased DN */
  while((*d = *q) != 0) {	/* loop by DN lables */
    qry->q_lptr[qlab++] = d++;	/* another label */
    e = q + *q + 1;		/* end of this label */
    if (*q > DNS_MAXLABEL	/* too long label? */
        || e > x)		/* or it ends past packet? */
      return 0;
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

  q += 4;
  pkt->p_sans = (unsigned char *)q; /* answers will start here */
  pkt->p_cur = (unsigned char *)q;  /* and current answer pointer is here */
  d = pkt->p_buf;
  if (q < x &&
      d[p_nscnt1] == 0 && d[p_nscnt2] == 0 &&
      d[p_arcnt1] == 0 && d[p_arcnt2] == 1 &&
      q[0] == 0 /* empty DN */ &&
      q[1] == (DNS_T_OPT>>8) && q[2] == (DNS_T_OPT&255)) {
    qlen = (((unsigned)q[3]) << 8) | q[4];
    /* 11 bytes are needed to encode minimal EDNS0 OPT record */
    if (qlen < DNS_MAXPACKET + 11)
      qlen = DNS_MAXPACKET;
    else if (qlen > sizeof(pkt->p_buf) - 11)
      qlen = sizeof(pkt->p_buf) - 11;
    else
      qlen -= 11;
    pkt->p_endp = d + qlen;
  }
  else
    pkt->p_endp = d + DNS_MAXPACKET;

  return 1;
}

#ifdef RECOGNIZE_IP4IN6
static const unsigned char *const ip6p =
  "\001f\001f\001f\001f\0010\0010\0010\0010"
  "\0010\0010\0010\0010\0010\0010\0010\0010"
  "\0010\0010\0010\0010\0010\0010\0010\0010"
  "\003ip6";
#endif

/* parse DN (as in 4.3.2.1.in-addr.arpa) to ip4addr_t */
static int
dntoip4addr(const unsigned char *q,
            unsigned UNUSED qlen0, unsigned qlab,
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

#ifdef NOSTATS
# define do_stats(x)
#else
# define do_stats(x) x
#endif

/* construct reply to a query. */
int replypacket(struct dnspacket *pkt, unsigned qlen, struct zone *zone) {

  struct dnsquery qry;			/* query structure */
  struct dnsqinfo qi;			/* query info structure */
  unsigned char *h = pkt->p_buf;	/* packet's header */
  const struct dslist *dsl;
  int found;
  extern int lazy; /*XXX hack*/

  pkt->p_substrr = 0;
  /* check global ACL */
  if (g_dsacl && g_dsacl->ds_stamp) {
    found = ds_acl_query(g_dsacl, pkt);
    if (found & NSQUERY_IGNORE) {
      do_stats(gstats.q_err += 1; gstats.b_in += qlen);
      return 0;
    }
  }
  else
    found = 0;

  if (!parsequery(pkt, qlen, &qry)) {
    do_stats(gstats.q_err += 1; gstats.b_in += qlen);
    return 0;
  }

  /* from now on, we see (almost?) valid dns query, should reply */

#define setnonauth(h) (h[p_f1] &= ~pf1_aa)
#define _refuse(code,lab) \
    do { setnonauth(h); h[p_f2] = (code); goto lab; } while(0)
#define refuse(code) _refuse(code, err_nz)
#define rlen() pkt->p_cur - h

  /* construct reply packet */

  /* identifier already in place */
  /* flags will be set up later */
  /* qdcount already set up in query */
  /* all counts (qd,an,ns,ar) are <= 255 due to size limit */
  h[p_ancnt1] = h[p_ancnt2] = 0;
  h[p_nscnt1] = h[p_nscnt2] = 0;
  h[p_arcnt1] = h[p_arcnt2] = 0;

  if (h[p_f1] & (pf1_opcode | pf1_aa | pf1_tc | pf1_qr)) {
    h[p_f1] = pf1_qr;
    refuse(DNS_R_NOTIMPL);
  }
  h[p_f1] |= pf1_qr;
  if (qry.q_class == DNS_C_IN)
    h[p_f1] |= pf1_aa;
  else if (qry.q_class != DNS_C_ANY) {
    if (version_req(pkt, &qry)) {
      do_stats(gstats.q_ok += 1; gstats.b_in += qlen; gstats.b_out += rlen());
      return rlen();
    }
    else
      refuse(DNS_R_REFUSED);
  }
  switch(qry.q_type) {
  case DNS_T_ANY: qi.qi_tflag = NSQUERY_ANY; break;
  case DNS_T_A:   qi.qi_tflag = NSQUERY_A;   break;
  case DNS_T_TXT: qi.qi_tflag = NSQUERY_TXT; break;
  case DNS_T_NS:  qi.qi_tflag = NSQUERY_NS;  break;
  case DNS_T_SOA: qi.qi_tflag = NSQUERY_SOA; break;
  case DNS_T_MX:  qi.qi_tflag = NSQUERY_MX;  break;
  default:
    if (qry.q_type >= DNS_T_TSIG)
      refuse(DNS_R_NOTIMPL);
    qi.qi_tflag = NSQUERY_OTHER;
  }
  qi.qi_tflag |= found;
  h[p_f2] = DNS_R_NOERROR;

  /* find matching zone */
  zone = (struct zone*)
      findqzone(zone, qry.q_dnlen, qry.q_dnlab, qry.q_lptr, &qi);
  if (!zone) /* not authoritative */
    refuse(DNS_R_REFUSED);

  /* found matching zone */
#undef refuse
#define refuse(code)  _refuse(code, err_z)
  do_stats(zone->z_stats.b_in += qlen);

  if (zone->z_dsacl && zone->z_dsacl->ds_stamp) {
    qi.qi_tflag |= ds_acl_query(zone->z_dsacl, pkt);
    if (qi.qi_tflag & NSQUERY_IGNORE) {
      do_stats(gstats.q_err += 1);
      return 0;
    }
  }

  if (!zone->z_stamp)	/* do not answer if not loaded */
    refuse(DNS_R_SERVFAIL);

  if (qi.qi_tflag & NSQUERY_REFUSE)
    refuse(DNS_R_REFUSED);

#ifdef do_hook_query_access
  if ((found = hook_query_access(zone, NULL, &qi))) {
    if (found < 0) return 0;
    refuse(DNS_R_REFUSED);
  }
#endif

  if (qi.qi_dnlab == 0) {	/* query to base zone: SOA and NS */

    found = NSQUERY_FOUND;

    if ((qi.qi_tflag & NSQUERY_SOA) && !addrr_soa(pkt, zone, 0))
      found = 0;
    else
    if ((qi.qi_tflag & NSQUERY_NS) && !addrr_ns(pkt, zone, 0))
      found = 0;
    if (!found) {
      pkt->p_cur = pkt->p_sans;
      h[p_ancnt2] = h[p_nscnt2] = 0;
      refuse(DNS_R_REFUSED);
    }

  }
  else /* not to zone base DN */
    found = 0;

  /* search the datasets */
  for(dsl = zone->z_dsl; dsl; dsl = dsl->dsl_next)
    found |= dsl->dsl_queryfn(dsl->dsl_ds, &qi, pkt);

  if (found & NSQUERY_ADDPEER) {
#ifdef NOIPv6
    addrr_a_txt(pkt, qi.qi_tflag, pkt->p_substrr,
                inet_ntoa(((struct sockaddr_in*)pkt->p_peer)->sin_addr),
                pkt->p_substds);
#else
    char subst[IPSIZE];
    if (getnameinfo(pkt->p_peer, pkt->p_peerlen,
                    subst, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0)
      subst[0] = '\0';
    addrr_a_txt(pkt, qi.qi_tflag, pkt->p_substrr, subst, pkt->p_substds);
#endif
  }

  /* now complete the reply: add AUTH etc sections */
  if (!found) {			/* negative result */
    addrr_soa(pkt, zone, 1);	/* add SOA if any to AUTHORITY */
    h[p_f2] = DNS_R_NXDOMAIN;
    do_stats(zone->z_stats.q_nxd += 1);
#ifdef do_hook_query_result
    hook_query_result(zone, NULL, &qi, 0);
#endif
  }
  else {
    if (!h[p_ancnt2]) {	/* positive reply, no answers */
      addrr_soa(pkt, zone, 1);	/* add SOA if any to AUTHORITY */
    }
    else if (zone->z_nns &&
             /* (!(qi.qi_tflag & NSQUERY_NS) || qi.qi_dnlab) && */
             !lazy)
      addrr_ns(pkt, zone, 1); /* add nameserver records to positive reply */
    do_stats(zone->z_stats.q_ok += 1);
#ifdef do_hook_query_result
    hook_query_result(zone, NULL, &qi, 1);
#endif
  }
  if (rlen() > DNS_MAXPACKET) {	/* add OPT record for long replies */
    /* as per parsequery(), we always have 11 bytes for minimal OPT record at
     * the end of our reply packet, OR rlen() does not exceed DNS_MAXPACKET */
    h[p_arcnt2] += 1;	/* arcnt is limited to 254 records */
    h = pkt->p_cur;
    *h++ = 0;			/* empty (root) DN */
    PACK16S(h, DNS_T_OPT);
    PACK16S(h, DNS_EDNS0_MAXPACKET);
    *h++ = 0; *h++ = 0;		/* RCODE and version */
    *h++ = 0; *h++ = 0;		/* rest of the TTL field */
    *h++ = 0; *h++ = 0;		/* RDLEN */
    pkt->p_cur = h;
    h = pkt->p_buf;		/* restore for rlen() to work */
  }
  do_stats(zone->z_stats.b_out += rlen());
  return rlen();

err_nz:
  do_stats(gstats.q_err += 1; gstats.b_in += qlen; gstats.b_out += rlen());
  return rlen();

err_z:
  do_stats(zone->z_stats.q_err += 1; zone->z_stats.b_out += rlen());
  return rlen();
}

#define fit(pkt, c, bytes) ((c) + (bytes) <= (pkt)->p_endp)


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
  unsigned nssize;			/* size of all NS RRs */
  unsigned tsize;			/* size of NS+glue recs */
  struct dnjump jump[MAX_NS*2+MAX_GLUE];/* jumps: for qDNs and for NSes */
  struct dnjump *nsjend;		/* last NS jump */
  struct dnjump *tjend;			/* last glue jump */
  unsigned char data[CACHEBUF_SIZE];
};

void init_zones_caches(struct zone *zonelist) {
  while(zonelist) {
    if (!zonelist->z_dsl) {
      char name[DNS_MAXDOMAIN];
      dns_dntop(zonelist->z_dn, name, sizeof(name));
      error(0, "missing data for zone `%s'", name);
    }
    zonelist->z_zsoa = tmalloc(struct zonesoa);
    /* for NS RRs, we allocate MAX_NS caches:
     * each stores one variant of NS rotation */
    zonelist->z_zns = (struct zonens *)emalloc(sizeof(struct zonens) * MAX_NS);
    zonelist = zonelist->z_next;
  }
}

/* update SOA RR cache */

int update_zone_soa(struct zone *zone, const struct dssoa *dssoa) {
   struct zonesoa *zsoa;
   unsigned char *cpos;
   struct dncompr compr;
   unsigned t;
   unsigned char *sizep;

   zsoa = zone->z_zsoa;
   zsoa->size = 0;
   if (!(zone->z_dssoa = dssoa)) return 1;

   cpos = dnc_init(&compr, zsoa->data, sizeof(zsoa->data),
                   zsoa->jump, zone->z_dn);

   cpos = dnc_add(&compr, cpos, zone->z_dn);
   PACK16S(cpos, DNS_T_SOA);
   PACK16S(cpos, DNS_C_IN);
   zsoa->ttloff = cpos - compr.buf;
   PACK32S(cpos, dssoa->dssoa_ttl);
   sizep = cpos;
   cpos += 2;
   cpos = dnc_add(&compr, cpos, dssoa->dssoa_odn);
   if (!cpos) return 0;
   cpos = dnc_add(&compr, cpos, dssoa->dssoa_pdn);
   if (!cpos) return 0;
   t = dssoa->dssoa_serial ? dssoa->dssoa_serial : zone->z_stamp;
   PACK32S(cpos, t);
   memcpy(cpos, dssoa->dssoa_n, 16); cpos += 16;
   zsoa->minttl = cpos - 4;
   t = cpos - sizep - 2;
   PACK16(sizep, t);
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
  pkt->p_buf[auth ? p_nscnt2 : p_ancnt2]++;
  return 1;
}

static unsigned char *
find_glue(struct zone *zone, const unsigned char *nsdn,
          struct dnspacket *pkt, const struct zone *zonelist) {
  struct dnsqinfo qi;
  unsigned lab;
  unsigned char dnbuf[DNS_MAXDN], *dp;
  unsigned char *dnlptr[DNS_MAXLABELS];
  const struct dslist *dsl;
  const struct zone *qzone;

  /* lowercase the nsdn and find label pointers */
  lab = 0; dp = dnbuf;
  while((*dp = *nsdn)) {
    const unsigned char *e = nsdn + *nsdn + 1;
    dnlptr[lab++] = dp++;
    while(++nsdn < e)
      *dp++ = dns_dnlc(*nsdn);
  }

  qzone = findqzone(zonelist, dp - dnbuf + 1, lab, dnlptr, &qi);
  if (!qzone)
    return NULL;

  /* pefrorm fake query */
  qi.qi_tflag = NSQUERY_A/*|NSQUERY_AAAA*/;
  dp = pkt->p_cur;
  for(dsl = qzone->z_dsl; dsl; dsl = dsl->dsl_next)
    dsl->dsl_queryfn(dsl->dsl_ds, &qi, pkt);

  if (dp == pkt->p_cur) {
    char name[DNS_MAXDOMAIN];
    dns_dntop(qi.qi_dn, name, sizeof(name));
    zlog(LOG_WARNING, zone, "no glue record(s) for %.60s NS found", name);
    return NULL;
  }

  return dp;
}

int update_zone_ns(struct zone *zone, const struct dsns *dsns, unsigned ttl,
                   const struct zone *zonelist) {
  struct zonens *zns;
  unsigned char *cpos, *sizep;
  struct dncompr compr;
  unsigned size, i, ns, nns;
  const unsigned char *nsdna[MAX_NS];
  const unsigned char *dn;
  unsigned char *nsrrs[MAX_NS], *nsrre[MAX_NS];
  unsigned nglue;
  struct dnspacket pkt;

  memset(&pkt, 0, sizeof(pkt));
  pkt.p_sans = pkt.p_cur = pkt.p_buf + p_hdrsize;
  pkt.p_endp = pkt.p_buf + CACHEBUF_SIZE + p_hdrsize;

  for(nns = 0; dsns; dsns = dsns->dsns_next) {
    i = 0;
    while(i < nns && !dns_dnequ(nsdna[i], dsns->dsns_dn))
      ++i;
    if (i < nns)
      continue;
    if (nns >= MAX_NS) {
      zlog(LOG_WARNING, zone,
           "too many NS records specified, only first %d will be used", MAX_NS);
      break;
    }
    nsdna[nns] = dsns->dsns_dn;
    if ((nsrrs[nns] = find_glue(zone, dsns->dsns_dn, &pkt, zonelist)))
      nsrre[nns] = pkt.p_cur;
    ++nns;
  }
  if (pkt.p_buf[p_ancnt1] || pkt.p_buf[p_ancnt2] > 254)	/* too many glue recs */
    return 0;
  nglue = pkt.p_buf[p_ancnt2];
  if (nns * 2 + nglue > sizeof(zns->jump)/sizeof(zns->jump[0]))
    return 0;

  memcpy(zone->z_nsdna, nsdna, nns * sizeof(nsdna[0]));
  memset(nsdna + nns, 0, (MAX_NS - nns) * sizeof(nsdna[0]));
  zone->z_nns = 0;	/* for now, in case of error return */
  zone->z_nsttl = ttl;

  /* fill up nns variants of NS RRs ordering:
   * zns is actually an array, not single structure */
  ns = 0;
  zns = zone->z_zns;
  for(;;) {
    cpos = dnc_init(&compr, zns->data, sizeof(zns->data),
                    zns->jump, zone->z_dn);

    for(i = 0; i < nns; ++i) {
      cpos = dnc_add(&compr, cpos, zone->z_dn);
      if (!cpos || cpos + 10 > compr.bend) return 0;
      PACK16S(cpos, DNS_T_NS);
      PACK16S(cpos, DNS_C_IN);
      PACK32S(cpos, ttl);
      sizep = cpos; cpos += 2;
      cpos = dnc_add(&compr, cpos, nsdna[i]);
      if (!cpos) return 0;
      size = cpos - sizep - 2;
      PACK16(sizep, size);
    }

    dnc_finish(&compr, cpos, &zns->nssize, &zns->nsjend);
    if (nglue)
      for(i = 0; i < nns; ++i)
        for(dn = nsrrs[i]; dn && dn < nsrre[i]; ) {
          /* pack the glue record. jump, type+class, ttl, size (= 4 or 16) */
          dn += 2;
          size = 10 + dn[2+2+4+1];
          cpos = dnc_add(&compr, cpos, zone->z_nsdna[i]);
          if (!cpos || cpos + size > compr.bend) return 0;
          memcpy(cpos, dn, size);
          dn += size; cpos += size;
        }
    dnc_finish(&compr, cpos, &zns->tsize, &zns->tjend);

    if (++ns >= nns) break;

    dn = nsdna[0];
    memmove(nsdna, nsdna + 1, (nns - 1) * sizeof(nsdna[0]));
    nsdna[nns - 1] = dn;
    ++zns;

  }
  zone->z_nns = nns;
  zone->z_nglue = nglue;

  return 1;
}

static int addrr_ns(struct dnspacket *pkt, const struct zone *zone, int auth) {
  unsigned cns = zone->z_cns;
  const struct zonens *zns = zone->z_zns + cns;
  if (!zone->z_nns)
    return 0;
  if (auth && dnc_final(pkt, zns->data, zns->tsize, zns->jump, zns->tjend)) {
    pkt->p_buf[p_nscnt2] += zone->z_nns;
    pkt->p_buf[p_arcnt2] += zone->z_nglue;
  }
  else if (!dnc_final(pkt, zns->data, zns->nssize, zns->jump, zns->nsjend))
    return 0;
  else
    pkt->p_buf[auth ? p_ancnt2 : p_nscnt2] += zone->z_nns;
  /* pick up next variation of NS ordering */
  ++cns;
  if (cns >= zone->z_nns)
    cns = 0;
  ((struct zone *)zone)->z_cns = cns;
  return 1;
}

static unsigned
checkrr_present(register unsigned char *c, register unsigned char *e,
                unsigned dtp, const void *data, unsigned dsz, unsigned ttl) {
  /* check whenever we already have this (type of) RR in reply,
   * ensure that all RRs of the same type has the same TTL */

  const unsigned char dtp1 = dtp >> 8, dtp2 = dtp & 255;
  unsigned t;

#define nextRR(c) ((c) + 12 + (c)[11])
#define hasRR(c,e) ((c) < (e))
#define sameRRT(c,dtp1,dtp2) ((c)[2] == (dtp1) && (c)[3] == (dtp2))
#define sameDATA(c,dsz,data) \
   ((c)[11] == (dsz) && memcmp((c)+12, (data), (dsz)) == 0)
#define rrTTL(c) ((c)+6)

  for(;;) {
    if (!hasRR(c,e))
      return ttl;
    if (sameRRT(c,dtp1,dtp2))
      break;
    c = nextRR(c);
  }

  /* found at least one RR with the same type as new */

  if (ttl >= (t = unpack32(rrTTL(c)))) {
    /* new ttl is either larger or the same as ttl of one of existing RRs */
    /* if we already have the same record, do nothing */
    if (sameDATA(c,dsz,data))
      return 0;
    /* check other records too */
    for(c = nextRR(c); hasRR(c,e); c = nextRR(c))
      if (sameRRT(c,dtp1,dtp2) && sameDATA(c,dsz,data))
        /* already has exactly the same data */
        return 0;
    return t; /* use existing, smaller TTL for new RR */
  }
  else { /* change TTLs of existing RRs to new, smaller one */
    int same = sameDATA(c,dsz,data);
    unsigned char *ttlnb = rrTTL(c);
    PACK32(ttlnb, ttl);
    for(c = nextRR(c); hasRR(c,e); c = nextRR(c))
      if (sameRRT(c,dtp1,dtp2)) {
        memcpy(rrTTL(c), ttlnb, 4);
        if (sameDATA(c,dsz,data))
          same = 1;
      }
    return same ? 0 : ttl;
  }
#undef nextRR
#undef hasRR
#undef sameRRT
#undef sameDATA
#undef rrTTL
}

/* add a new record into answer, check for dups.
 * We just ignore any data that exceeds packet size */
void addrr_any(struct dnspacket *pkt, unsigned dtp,
               const void *data, unsigned dsz,
               unsigned ttl) {
  register unsigned char *c = pkt->p_cur;
  ttl = checkrr_present(pkt->p_sans, c, dtp, data, dsz, ttl);
  if (!ttl) return; /* if RR is already present, do nothing */

  if (!fit(pkt, c, 12 + dsz)) {
    setnonauth(pkt->p_buf); /* non-auth answer as we can't fit the record */
    return;
  }
  *c++ = 192; *c++ = p_hdrsize;	/* jump after header: query DN */
  PACK16S(c, dtp);
  PACK16S(c, DNS_C_IN);
  PACK32S(c, ttl);
  PACK16S(c, dsz);
  memcpy(c, data, dsz);
  pkt->p_cur = c + dsz;
  pkt->p_buf[p_ancnt2] += 1; /* increment numanswers */
}

void
addrr_a_txt(struct dnspacket *pkt, unsigned qtflag,
            const char *rr, const char *subst,
            const struct dataset *ds) {
  if (qtflag & NSQUERY_A)
    addrr_any(pkt, DNS_T_A, rr, 4, ds->ds_ttl);
  if (rr[4] && (qtflag & NSQUERY_TXT)) {
    char sb[TXTBUFSIZ];
    unsigned sl = txtsubst(sb + 1, rr + 4, subst, ds);
    sb[0] = sl;
    addrr_any(pkt, DNS_T_TXT, sb, sl + 1, ds->ds_ttl);
  }
}

static int version_req(struct dnspacket *pkt, const struct dnsquery *qry) {
  register unsigned char *c;
  unsigned dsz;

  if (!show_version)
    return 0;
  if (qry->q_class != DNS_C_CH || qry->q_type != DNS_T_TXT)
    return 0;
  if ((qry->q_dnlen != 16 || memcmp(qry->q_dn, "\7version\6server", 16)) &&
      (qry->q_dnlen != 14 || memcmp(qry->q_dn, "\7version\4bind", 14)))
    return 0;

  c = pkt->p_cur;
  *c++ = 192; *c++ = p_hdrsize; /* jump after header: query DN */
  *c++ = DNS_T_TXT>>8; *c++ = DNS_T_TXT;
  *c++ = DNS_C_CH>>8; *c++ = DNS_C_CH;
  *c++ = 0; *c++ = 0; *c++ = 0; *c++ = 0; /* ttl */
  dsz = strlen(show_version) + 1;
  PACK16(c, dsz); c += 2;       /* dsize */
  *c++ = --dsz;
  memcpy(c, show_version, dsz);
  pkt->p_cur = c + dsz;
  pkt->p_buf[p_ancnt2] += 1; /* increment numanswers */
  return 1;
}

void logreply(const struct dnspacket *pkt, FILE *flog, int flushlog) {
  char cbuf[DNS_MAXDOMAIN + IPSIZE + 50];
  char *cp = cbuf;
  const unsigned char *const q = pkt->p_sans - 4;

  cp += sprintf(cp, "%lu ", (unsigned long)time(NULL));
#ifndef NOIPv6
  if (getnameinfo(pkt->p_peer, pkt->p_peerlen,
                  cp, NI_MAXHOST, NULL, 0,
                  NI_NUMERICHOST) == 0)
    cp += strlen(cp);
  else
    *cp++ = '?';
#else
  strcpy(cp, inet_ntoa(((struct sockaddr_in*)pkt->p_peer)->sin_addr.s_addr));
  cp += strlen(cp);
#endif
  *cp++ = ' ';
  cp += dns_dntop(pkt->p_buf + p_hdrsize, cp, DNS_MAXDOMAIN);
  cp += sprintf(cp, " %s %s: %s/%u/%d\n",
      dns_typename(((unsigned)q[0]<<8)|q[1]),
      dns_classname(((unsigned)q[2]<<8)|q[3]),
      dns_rcodename(pkt->p_buf[p_f2] & pf2_rcode),
      pkt->p_buf[p_ancnt2], pkt->p_cur - pkt->p_buf);
  if (flushlog)
    write(fileno(flog), cbuf, cp - cbuf);
  else
    fwrite(cbuf, cp - cbuf, 1, flog);
}
