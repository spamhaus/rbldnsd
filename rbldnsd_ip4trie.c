/* $Id$
 * ip4trie dataset type: IP4 CIDR ranges with A and TXT values.
 * Only one value per range allowed.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"

/* for exclusions, we're using special pointer
 * to distinguish exclusions from glue nodes
 * which have node->data == NULL */
#define excluded_rr ((const char*)1)

struct dsdata {
  struct ip4trie trie;
  const char *def_rr;	/* default RR */
};

definedstype(ip4trie, DSTF_IP4REV, "set of (ip4cidr, value) pairs");

static void ds_ip4trie_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  memset(dsd, 0, sizeof(*dsd));
}

static void ds_ip4trie_start(struct dataset *ds) {
  ds->ds_dsd->def_rr = def_rr;
}

static int
ds_ip4trie_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  ip4addr_t a;
  int bits;
  const char *rr;
  unsigned rrl;
  struct ip4trie_node *node;

  int not;

  if (*s == ':') {
    if (!(rrl = parse_a_txt(s, &rr, def_rr, dsc)))
      return 1;
    if (!(dsd->def_rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
    return 1;
  }

  if (*s == '!') {
    not = 1;
    ++s; SKIPSPACE(s);
  }
  else
    not = 0;
  if ((bits = ip4cidr(s, &a, &s)) <= 0 ||
      (*s && !ISSPACE(*s) && !ISCOMMENT(*s) && *s != ':')) {
    dswarn(dsc, "invalid address");
    return 1;
  }
  if (accept_in_cidr)
    a &= ip4mask(bits);
  else if (a & ~ip4mask(bits)) {
    dswarn(dsc, "invalid range (non-zero host part)");
    return 1;
  }
  if (dsc->dsc_ip4maxrange && dsc->dsc_ip4maxrange <= ~ip4mask(bits)) {
    dswarn(dsc, "too large range (%u) ignored (%u max)",
           ~ip4mask(bits) + 1, dsc->dsc_ip4maxrange);
    return 1;
  }
  if (not)
    rr = excluded_rr;
  else {
    SKIPSPACE(s);
    if (!*s || ISCOMMENT(*s))
      rr = dsd->def_rr;
    else if (!(rrl = parse_a_txt(s, &rr, dsd->def_rr, dsc)))
      return 1;
    else if (!(rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
  }

  node = ip4trie_addnode(&dsd->trie, a, bits, ds->ds_mp);
  if (!node)
    return 0;

  if (node->ip4t_data) {
    dswarn(dsc, "duplicated entry for %s/%d", ip4atos(a), bits);
    return 1;
  }
  node->ip4t_data = rr;
  ++dsd->trie.ip4t_nents;

  return 1;
}

static void ds_ip4trie_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  dsloaded(dsc, "ent=%u nodes=%u mem=%u",
           dsd->trie.ip4t_nents, dsd->trie.ip4t_nnodes,
           dsd->trie.ip4t_nnodes * sizeof(struct ip4trie_node));
}

static int
ds_ip4trie_query(const struct dataset *ds, const struct dnsqinfo *qi,
                 struct dnspacket *pkt) {
  const char *rr;

  if (!qi->qi_ip4valid) return 0;

  rr = ip4trie_lookup(&ds->ds_dsd->trie, qi->qi_ip4);

  if (!rr || rr == excluded_rr)
    return 0;

  addrr_a_txt(pkt, qi->qi_tflag, rr,
              qi->qi_tflag & NSQUERY_TXT ? ip4atos(qi->qi_ip4) : NULL, ds);
  return 1;
}

#ifndef NO_MASTER_DUMP

static ip4addr_t
ds_ip4trie_dump_node(const struct ip4trie_node *n,
                     const struct ip4trie_node *super, ip4addr_t a,
                     const struct dataset *ds, FILE *f) {
  if (n->ip4t_data && (!super || super->ip4t_data != n->ip4t_data)) {
     if (super && super->ip4t_data != excluded_rr && a < n->ip4t_prefix)
       dump_ip4range(a, n->ip4t_prefix - 1, super->ip4t_data, ds, f);
     a = n->ip4t_prefix;
     super = n;
  }
  if (n->ip4t_left)
    if ((a = ds_ip4trie_dump_node(n->ip4t_left, super, a, ds, f)) == 0)
      return 0;
  if (n->ip4t_right)
    if ((a = ds_ip4trie_dump_node(n->ip4t_right, super, a, ds, f)) == 0)
      return 0;
  if (super == n) {
    ip4addr_t b = n->ip4t_prefix | ~ip4mask(n->ip4t_bits);
    if (a <= b && n->ip4t_data != excluded_rr)
      dump_ip4range(a, b, n->ip4t_data, ds, f);
    return b == 0xffffffffu ? 0 : b + 1;
  }
  else
    return a;
}

static void
ds_ip4trie_dump(const struct dataset *ds,
                const unsigned char UNUSED *unused_odn,
                FILE *f) {
  if (ds->ds_dsd->trie.ip4t_root)
    ds_ip4trie_dump_node(ds->ds_dsd->trie.ip4t_root, NULL, 0, ds, f);
}

#endif
