/* ACL (Access Control Lists) implementation for rbldnsd.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "rbldnsd.h"
#include "btrie.h"

struct dsdata {
  struct btrie *ip4_trie;
#ifndef NO_IPv6
  struct btrie *ip6_trie;
#endif
  const char *def_rr;
  const char *def_action;
};

/* special cases for pseudo-RRs */
static const struct {
  const char *name;
  unsigned long rr;
} keywords[] = {
  /* ignore (don't answer) queries from this IP */
#define RR_IGNORE	1
 { "ignore", RR_IGNORE },
 { "blackhole", RR_IGNORE },
 /* refuse *data* queries from this IP (but not metadata) */
#define RR_REFUSE	2
 { "refuse", RR_REFUSE },
 /* pretend the zone is completely empty */
#define RR_EMPTY	3
 { "empty", RR_EMPTY },
 /* a 'whitelist' entry: pretend this netrange isn't here */
#define RR_PASS		4
 { "pass", RR_PASS },
};

static void ds_acl_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  memset(dsd, 0, sizeof(*dsd));
}

static void ds_acl_start(struct dataset *ds) {
  struct dsdata *dsd = ds->ds_dsd;

  dsd->def_rr = def_rr;
  dsd->def_action = (char*)RR_IGNORE;
  if (!dsd->ip4_trie) {
    dsd->ip4_trie = btrie_init(ds->ds_mp);
#ifndef NO_IPv6
    dsd->ip6_trie = btrie_init(ds->ds_mp);
#endif
  }
}

static const char *keyword(const char *s) {
  const char *k, *p;
  unsigned i;
  if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z')))
    return NULL;
  for (i = 0; i < sizeof(keywords)/sizeof(keywords[0]); ++i)
    for (k = keywords[i].name, p = s;;)
      if ((*p >= 'A' && *p <= 'Z' ? *p - 'A' + 'a' : *p) != *k++)
        break;
      else if (!*++p || *p == ':' || ISSPACE(*p) || ISCOMMENT(*p))
        return (const char *)(keywords[i].rr);
  return NULL;
}

static int
ds_acl_parse_val(char *s, const char **rr_p, struct dsdata *dsd,
                 struct dsctx *dsc) {
  int r;
  if (*s == '=') {
    if ((*rr_p = keyword(s+1)))
      return 0;
    dswarn(dsc, "invalid keyword");
    return -1;
  }
  if (*s == ':' && (*rr_p = keyword(s+1)))
    return 0;
  r = parse_a_txt(s, rr_p, dsd->def_rr, dsc);
  return r ? r : -1;
}

#define VALID_TAIL(c) ((c) == '\0' || ISSPACE(c) ||  ISCOMMENT(c) || (c) == ':')

static int
ds_acl_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  char *tail;
  ip4addr_t ip4addr;
  ip6oct_t addr[IP6ADDR_FULL];
  const char *ipstring;
  struct btrie *trie;
  int bits;
  const char *rr;
  int rrl;

  /* "::" can not be a valid start to a default RR setting ("invalid A
   * RR") but it can be a valid beginning to an ip6 address
   * (e.g. "::1")
   */
  if ((*s == ':' && s[1] != ':') || *s == '=') {
    if ((rrl = ds_acl_parse_val(s, &rr, dsd, dsc)) < 0)
      return 1;
    else if (!rrl)
      dsd->def_action = rr;
    else if (!(rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
    dsd->def_rr = dsd->def_action = rr;
    return 1;
  }

  if ((bits = ip4cidr(s, &ip4addr, &tail)) >= 0 && VALID_TAIL(tail[0])) {
    if (accept_in_cidr)
      ip4addr &= ip4mask(bits);
    else if (ip4addr & ~ip4mask(bits)) {
      dswarn(dsc, "invalid range (non-zero host part)");
      return 1;
    }
    if (dsc->dsc_ip4maxrange && dsc->dsc_ip4maxrange <= ~ip4mask(bits)) {
      dswarn(dsc, "too large range (%u) ignored (%u max)",
             ~ip4mask(bits) + 1, dsc->dsc_ip4maxrange);
      return 1;
    }
    trie = dsd->ip4_trie;
    ip4unpack(addr, ip4addr);
    ipstring = ip4atos(ip4addr);
    s = tail;
  }
#ifndef NO_IPv6
  else if ((bits = ip6cidr(s, addr, &tail)) >= 0 && VALID_TAIL(tail[0])) {
    int non_zero_host = ip6mask(addr, addr, IP6ADDR_FULL, bits);
    if (non_zero_host && !accept_in_cidr) {
      dswarn(dsc, "invalid range (non-zero host part)");
      return 1;
    }
    trie = dsd->ip6_trie;
    ipstring = ip6atos(addr, IP6ADDR_FULL);
    s = tail;
  }
#endif
  else {
    dswarn(dsc, "invalid address");
    return 1;
  }

  SKIPSPACE(s);
  if (!*s || ISCOMMENT(*s))
    rr = dsd->def_action;
  else if ((rrl = ds_acl_parse_val(s, &rr, dsd, dsc)) < 0)
    return 1;
  else if (rrl && !(rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
    return 0;

  switch(btrie_add_prefix(trie, addr, bits, rr)) {
  case BTRIE_OKAY:
    return 1;
  case BTRIE_DUPLICATE_PREFIX:
    dswarn(dsc, "duplicated entry for %s/%d", ipstring, bits);
    return 1;
  case BTRIE_ALLOC_FAILED:
  default:
    return 0;
  }
}

static void ds_acl_finish(struct dataset *ds, struct dsctx *dsc) {
  dsloaded(dsc, "loaded");
  dslog(LOG_INFO, dsc, "ip4 trie: %s", btrie_stats(ds->ds_dsd->ip4_trie));
#ifndef NO_IPv6
  dslog(LOG_INFO, dsc, "ip6 trie: %s", btrie_stats(ds->ds_dsd->ip6_trie));
#endif
}

int ds_acl_query(const struct dataset *ds, struct dnspacket *pkt) {
  const struct sockaddr *sa = pkt->p_peer;
  const char *rr;

  if (sa->sa_family == AF_INET) {
    const struct sockaddr_in *sin = (const struct sockaddr_in *)pkt->p_peer;
    if (pkt->p_peerlen < sizeof(*sin))
      return 0;
    rr = btrie_lookup(ds->ds_dsd->ip4_trie,
                      (const btrie_oct_t *)&sin->sin_addr.s_addr, 32);
  }
#ifndef NO_IPv6
  else if (sa->sa_family == AF_INET6) {
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)pkt->p_peer;
    if (pkt->p_peerlen < sizeof(*sin6))
      return 0;
    rr = btrie_lookup(ds->ds_dsd->ip6_trie,
                      sin6->sin6_addr.s6_addr, 8 * IP6ADDR_FULL);
  }
#endif
  else {
    return 0;
  }

  switch((unsigned long)rr) {
  case 0: return 0;
  case RR_IGNORE:	return NSQUERY_IGNORE;
  case RR_REFUSE:	return NSQUERY_REFUSE;
  case RR_EMPTY:	return NSQUERY_EMPTY;
  case RR_PASS:		return 0;
  }
  if (!pkt->p_substrr) {
    pkt->p_substrr = rr;
    pkt->p_substds = ds;
  }
  return NSQUERY_ALWAYS;
}

/*definedstype(acl, DSTF_SPECIAL, "Access Control List dataset");*/
const struct dstype dataset_acl_type = {
  "acl", DSTF_SPECIAL, sizeof(struct dsdata),
  ds_acl_reset, ds_acl_start, ds_acl_line, ds_acl_finish,
  NULL, NULL, "Access Control List dataset"
};
