/* $Id$
 * ip4trie dataset type: IP4 CIDR ranges with A and TXT values.
 * Only one value per range allowed.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"

struct node {
  ip4addr_t prefix;
  ip4addr_t bits;
  struct node *left, *right;
  const char *rr;
};

#define excluded_rr ((const char*)1)

struct dsdata {
  struct node *tree;
  const char *def_rr;
  unsigned nents, nnodes;
};

definedstype(ip4trie, DSTF_IP4REV, "set of (ip4cidr, value) pairs");

#define prefixmatch(p1, p2, len) ((((p1)^(p2))&ip4mask(len))?0:1)
#define bitset(prefix, bit) ((prefix)&(0x80000000>>(bit)))

static void ds_ip4trie_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  memset(dsd, 0, sizeof(*dsd));
}

static void ds_ip4trie_start(struct dataset *ds) {
  ds->ds_dsd->def_rr = def_rr;
}


static struct node *
createnode(struct mempool *mp, ip4addr_t prefix, unsigned bits) {
  struct node *node = mp_talloc(mp, struct node);
  if (node) {
    node->left = node->right = NULL;
    node->rr = NULL;
    node->prefix = prefix;
    node->bits = bits;
  }
  return node;
}

static inline void
linknode(struct node *parent, struct node *node) {
  if (bitset(node->prefix, parent->bits))
    parent->right = node;
  else
    parent->left = node;
}

static struct node *
ds_ip4trie_addnode(struct dsdata *dsd, ip4addr_t prefix, unsigned bits,
		   struct mempool *mp) {
  struct node *node = dsd->tree;
  struct node *match = NULL;

  for(;;) {

    if (!node) {
      ++dsd->nnodes;
      if (!(node = createnode(mp, prefix, bits)))
	return NULL;
      if (match)
	linknode(match, node);
      else
	dsd->tree = node;
      return node;
    }

    if (node->bits > bits || !prefixmatch(node->prefix, prefix, node->bits)) {
      struct node *newnode;
      ip4addr_t diff = (prefix ^ node->prefix) & ip4mask(bits);
      unsigned cbits = 0;
      while((diff & ip4mask(cbits+1)) == 0)
	++cbits;
      ++dsd->nnodes;
      if (!(newnode = createnode(mp, prefix & ip4mask(cbits), cbits)))
	return NULL;
      linknode(newnode, node);
      if (match)
	linknode(match, newnode);
      else
	dsd->tree = newnode;
      if (cbits != bits) {
	++dsd->nnodes;
	match = newnode;
	if (!(newnode = createnode(mp, prefix, bits)))
	  return NULL;
	linknode(match, newnode);
      }
      return newnode;
    }

    if (node->bits == bits)
      return node;

    match = node;
    if (bitset(prefix, node->bits))
      node = node->right;
    else
      node = node->left;
  }

}

static int
ds_ip4trie_line(struct dataset *ds, char *s, int lineno) {
  struct dsdata *dsd = ds->ds_dsd;
  ip4addr_t a;
  unsigned bits;
  const char *rr;
  unsigned rrl;
  struct node *node;

  int not;

  if (*s == ':') {
    if (!(rrl = parse_a_txt(lineno, s, &rr, def_rr)))
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
  if (!(bits = ip4parse_cidr(s, &a, &s)) ||
      (*s && !ISSPACE(*s) && !ISCOMMENT(*s) && *s != ':')) {
    dswarn(lineno, "invalid address");
    return 1;
  }
  if (not)
    rr = excluded_rr;
  else {
    SKIPSPACE(s);
    if (!*s || ISCOMMENT(*s))
      rr = dsd->def_rr;
    else if (!(rrl = parse_a_txt(lineno, s, &rr, dsd->def_rr)))
      dswarn(lineno, "invalid value");
    else if (!(rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
  }

  node = ds_ip4trie_addnode(dsd, a, bits, ds->ds_mp);
  if (!node)
    return 0;

  if (node->rr) {
    dswarn(lineno, "duplicated entry for %s/%d", ip4atos(a), bits);
    return 1;
  }
  node->rr = rr;
  ++dsd->nents;

  return 1;
}

static void ds_ip4trie_finish(struct dataset *ds) {
  struct dsdata *dsd = ds->ds_dsd;
  dsloaded("ent=%u nodes=%u mem=%u",
	   dsd->nents, dsd->nnodes, dsd->nnodes * sizeof(struct node));
}

static const char *
ds_ip4trie_find(const struct dsdata *dsd, ip4addr_t q) {
  const struct node *node = dsd->tree;
  const char *match = NULL;
  while(node && prefixmatch(node->prefix, q, node->bits)) {
    if (node->rr)
      match = node->rr;
    if (bitset(q, node->bits))
      node = node->right;
    else
      node = node->left;
  }
  return match;
}

int
ds_ip4trie_query(const struct dataset *ds, const struct dnsqinfo *qi,
		 struct dnspacket *pkt) {
  const struct dsdata *dsd = ds->ds_dsd;
  ip4addr_t q = qi->qi_ip4;
  const char *rr;

  if (!qi->qi_ip4valid) return 0;

  rr = ds_ip4trie_find(dsd, q);
  if (!rr || rr == excluded_rr)
    return 0;

  addrr_a_txt(pkt, qi->qi_tflag, rr,
	      (qi->qi_tflag & NSQUERY_TXT) ? ip4atos(q) : NULL,
	      ds);
  return 1;
}

static void
ds_ip4trie_dump(const struct dataset UNUSED *ds,
		const unsigned char UNUSED *unused_odn,
		FILE UNUSED *f) {
  fprintf(stderr, "%s: can't dump ip4trie\n", progname);
}
