/* $Id$
 * ip4trie dataset type: IP4 CIDR ranges with A and TXT values.
 * Only one value per range allowed.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"

struct node {	/* trie node */
  ip4addr_t prefix;	/* the address prefix, high bits */
  ip4addr_t bits;	/* number of significant bits in prefix */
#ifdef IP4TRIE_DEBUG
  char pstr[32];
#endif
  struct node *right;	/* if (bit+1)'s bit in prefix is 1, go here */
  struct node *left;	/* or else here. */
  const char *rr;	/* RR if any assotiated with this node */
};

/* for exclusions, we're using special pointer
 * to distinguish exclusions from glue nodes
 * which have node->rr == NULL */
#define excluded_rr ((const char*)1)

struct dsdata {
  struct node *tree;	/* root of the tree */
  const char *def_rr;	/* default RR */
  unsigned nents;	/* number of entries so far */
  unsigned nnodes;	/* total number of nodes in tree */
};

definedstype(ip4trie, DSTF_IP4REV, "set of (ip4cidr, value) pairs");

/* test whenever first len high bits in p1 and p2 are equal */
#define prefixmatch(p1, p2, len) ((((p1)^(p2))&ip4mask(len))?0:1)
/* test whenether bit's number bit is set in prefix.
 * Most significant bit is bit 0, least significant - bit #31 */
#define bitset(prefix, bit) ((prefix)&(0x80000000>>(bit)))

static void ds_ip4trie_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  memset(dsd, 0, sizeof(*dsd));
}

static void ds_ip4trie_start(struct dataset *ds) {
  ds->ds_dsd->def_rr = def_rr;
}

/* create and initialize new node with a given prefix/bits */
static struct node *
createnode(ip4addr_t prefix, unsigned bits, struct mempool *mp) {
  struct node *node = mp_talloc(mp, struct node);
  if (!node)
    return NULL;
  node->left = node->right = NULL;
  node->rr = NULL;
  node->prefix = prefix;
  node->bits = bits;
#ifdef IP4TRIE_DEBUG
  { unsigned c;
    memset(node->pstr, '0', 32);
    for(c = 0; c < bits; ++c) if (bitset(prefix, c)) node->pstr[c] = '1';
  }
#endif
  return node;
}

#ifdef IP4TRIE_DEBUG

static char *p2s(ip4addr_t prefix, unsigned bits) {
  static char buf[60];
  unsigned c;
  for(c = 0; c < bits; ++c) buf[c] = bitset(prefix, c) ? '1' : '0';
  sprintf(buf + c, "/%d %s/%d", bits, ip4atos(prefix), bits);
  return buf;
}

#define n2s(node) p2s((node)->prefix, (node)->bits)

static void print_tree(const struct node *node, const char *name, int level) {
  printf("%*s: ", level * 2, name);
  if (!node)
    printf("(null)\n");
  else {
    printf("%s\n", n2s(node));
    print_tree(node->left, "left ", level + 1);
    print_tree(node->right, "right", level + 1);
  }
}

#define dprintf(x) printf x

#else

#define dprintf(x)
#define print_tree(node, name, level)

#endif

/* link node to either left or right of parent,
 * assuming both parent's links are NULL */
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
  struct node *node, **last;

#ifdef IP4TRIE_DEBUG
  static int c;
  dprintf(("%d addnode: %s\n", c++, p2s(prefix, bits)));
#endif

  for(last = &dsd->tree;
      (node = *last) != NULL;
      last = bitset(prefix, node->bits) ? &node->right : &node->left) {

    if (node->bits > bits || !prefixmatch(node->prefix, prefix, node->bits)) {
      /* new node should be inserted before the given node */
      struct node *newnode;

      /* Find number of common (equal) bits */
      ip4addr_t diff = (prefix ^ node->prefix) & ip4mask(bits);
      unsigned cbits;
      if (!diff) /* no difference, all bits are the same */
        cbits = bits;
      else {
        cbits = 0;
        while((diff & ip4mask(cbits+1)) == 0)
          ++cbits;
      }
      ++dsd->nnodes;
      if (!(newnode = createnode(prefix & ip4mask(cbits), cbits, mp)))
        return NULL;
      linknode(newnode, node);
      *last = newnode;
      if (cbits == bits)
        return newnode;
      /* so we just inserted a glue node, now insert real one */
      ++dsd->nnodes;
      if (!(node = createnode(prefix, bits, mp)))
          return NULL;
      linknode(newnode, node);
      return node;
    }

    /* node's prefix matches */
    if (node->bits == bits)	/* if number of bits are the same too, */
      return node;		/* ..we're found exactly the same prefix */

  }

  /* no more nodes, create simple new node */
  ++dsd->nnodes;
  if (!(node = createnode(prefix, bits, mp)))
    return NULL;
  *last = node;
  return node;
}

static int
ds_ip4trie_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  ip4addr_t a;
  int bits;
  const char *rr;
  unsigned rrl;
  struct node *node;

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
      (!accept_in_cidr && (a & ~ip4mask(bits))) ||
      (*s && !ISSPACE(*s) && !ISCOMMENT(*s) && *s != ':')) {
    dswarn(dsc, "invalid address");
    return 1;
  }
  if (not)
    rr = excluded_rr;
  else {
    SKIPSPACE(s);
    if (!*s || ISCOMMENT(*s))
      rr = dsd->def_rr;
    else if (!(rrl = parse_a_txt(s, &rr, dsd->def_rr, dsc)))
      dswarn(dsc, "invalid value");
    else if (!(rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
  }

  node = ds_ip4trie_addnode(dsd, a, bits, ds->ds_mp);
  if (!node)
    return 0;
  print_tree(dsd->tree, "top", 0);

  if (node->rr) {
    dswarn(dsc, "duplicated entry for %s/%d", ip4atos(a), bits);
    return 1;
  }
  node->rr = rr;
  ++dsd->nents;

  return 1;
}

static void ds_ip4trie_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
#ifdef IP4TRIE_DEBUG
  print_tree(dsd->tree, "final", 0);
  fflush(stdout);
#endif
  dsloaded(dsc, "ent=%u nodes=%u mem=%u",
           dsd->nents, dsd->nnodes, dsd->nnodes * sizeof(struct node));
}

int
ds_ip4trie_query(const struct dataset *ds, const struct dnsqinfo *qi,
                 struct dnspacket *pkt) {
  ip4addr_t q;
  const struct node *node;
  const char *rr = NULL;

  if (!qi->qi_ip4valid) return 0;

  q = qi->qi_ip4;
  node = ds->ds_dsd->tree;
  while(node && prefixmatch(node->prefix, q, node->bits)) {
    if (node->rr)
      rr = node->rr;
    if (bitset(q, node->bits))
      node = node->right;
    else
      node = node->left;
  }

  if (!rr || rr == excluded_rr)
    return 0;

  addrr_a_txt(pkt, qi->qi_tflag, rr,
              qi->qi_tflag & NSQUERY_TXT ? ip4atos(q) : NULL, ds);
  return 1;
}

static int
ds_ip4trie_dump_octets(FILE *f, unsigned idx, ip4addr_t a, unsigned cnt,
                       const struct node *n, const struct dataset *ds) {
  char name[16];
  static const char * const fmt[4] = {
     "%u.%u.%u.%u", "*.%u.%u.%u", "*.%u.%u", "*.%u"
  };
  const unsigned bits = 8 * idx;
  for(;;) {
    sprintf(name, fmt[idx], a&255, (a>>8)&255, (a>>16)&255, (a>>24));
    dump_a_txt(name, n->rr, ip4atos(a<<bits), ds, f);
    if (!--cnt)
      break;
    ++a;
  }
  return 0;
}

static int
ds_ip4trie_dump_range(FILE *f, ip4addr_t a, ip4addr_t b,
                      const struct node *n, const struct dataset *ds) {

  if (n->rr == excluded_rr) return 0;

#define fn(idx,start,count) ds_ip4trie_dump_octets(f, idx, start, count, n, ds)
#define ip4range_expand_octet(bits)               \
  if ((a | 255u) >= b) {                          \
    if (b - a == 255u)                            \
      return fn((bits>>3)+1, a>>8, 1);            \
    else                                          \
      return fn(bits>>3, a, b - a + 1);           \
  }                                               \
  if (a & 255u) {                                 \
    if (!fn(bits>>3, a, 256u - (a & 255u)))       \
      return 0;                                   \
    a = (a >> 8) + 1;                             \
  }                                               \
  else                                            \
    a >>= 8;                                      \
  if ((b & 255u) != 255u) {                       \
    if (!fn((bits>>3), (b & ~255u), (b&255u)+1))  \
      return 0;                                   \
    b = (b >> 8) - 1;                             \
  }                                               \
  else                                            \
    b >>= 8

  ip4range_expand_octet(0);
  ip4range_expand_octet(8);
  ip4range_expand_octet(16);
  return fn(3, a, b - a + 1);
}

static ip4addr_t
ds_ip4trie_dump_node(FILE *f, const struct node *n,
                     const struct node *super, ip4addr_t a,
                     const struct dataset *ds) {
  if (n->rr && (!super || super->rr != n->rr)) {
     if (super && a < n->prefix)
       ds_ip4trie_dump_range(f, a, n->prefix - 1, super, ds);
     a = n->prefix;
     super = n;
  }
  if (n->left)
    if ((a = ds_ip4trie_dump_node(f, n->left, super, a, ds)) == 0)
      return 0;
  if (n->right)
    if ((a = ds_ip4trie_dump_node(f, n->right, super, a, ds)) == 0)
      return 0;
  if (super == n) {
    ip4addr_t b = n->prefix | ~ip4mask(n->bits);
    if (a <= b)
      ds_ip4trie_dump_range(f, a, b, n, ds);
    return b == 0xffffffffu ? 0 : b + 1;
  }
  else
    return a;
}

static void
ds_ip4trie_dump(const struct dataset *ds,
                const unsigned char UNUSED *unused_odn,
                FILE *f) {
  if (ds->ds_dsd->tree)
    ds_ip4trie_dump_node(f, ds->ds_dsd->tree, NULL, 0, ds);
}
