/* ip6trie dataset type: IP6 CIDR ranges with A and TXT values.
 * Only one value per range allowed.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"
#include "btrie.h"

struct dsdata {
  struct btrie *btrie;
  const char *def_rr;	/* default RR */
};

definedstype(ip6trie, DSTF_IP6REV, "set of (ip6cidr, value) pairs");

static void
ds_ip6trie_reset(struct dsdata *dsd, int UNUSED unused_freeall)
{
  memset(dsd, 0, sizeof(*dsd));
}

static void
ds_ip6trie_start(struct dataset *ds)
{
  struct dsdata *dsd = ds->ds_dsd;

  dsd->def_rr = def_rr;
  if (!dsd->btrie)
    dsd->btrie = btrie_init(ds->ds_mp);
}

static int
ds_ip6trie_line(struct dataset *ds, char *s, struct dsctx *dsc)
{
  struct dsdata *dsd = ds->ds_dsd;
  const char *rr;
  unsigned rrl;
  int bits, excl, non_zero_host;
  ip6oct_t addr[IP6ADDR_FULL];

  /* "::" can not be a valid start to a default RR setting ("invalid A
   * RR") but it can be a valid beginning to an ip6 address
   * (e.g. "::1")
   */
  if (*s == ':' && s[1] != ':') {
    if (!(rrl = parse_a_txt(s, &rr, def_rr, dsc)))
      return 1;
    if (!(dsd->def_rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
    return 1;
  }

  excl = *s == '!';
  if (excl) {
    ++s;
    SKIPSPACE(s);
  }

  bits = ip6cidr(s, addr, &s);
  if (bits < 0 || (*s && !ISSPACE(*s) && !ISCOMMENT(*s) && *s != ':')) {
    dswarn(dsc, "invalid address");
    return 1;
  }
  non_zero_host = ip6mask(addr, addr, IP6ADDR_FULL, bits);
  if (non_zero_host && !accept_in_cidr) {
    dswarn(dsc, "invalid range (non-zero host part)");
    return 1;
  }

  SKIPSPACE(s);
  if (excl)
    rr = NULL;
  else if (!*s || ISCOMMENT(*s))
    rr = dsd->def_rr;
  else if (!(rrl = parse_a_txt(s, &rr, dsd->def_rr, dsc)))
    return 1;
  else if (!(rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
    return 0;

  switch(btrie_add_prefix(dsd->btrie, addr, bits, rr)) {
  case BTRIE_OKAY:
    return 1;
  case BTRIE_DUPLICATE_PREFIX:
    dswarn(dsc, "duplicated entry for %s/%d",
           ip6atos(addr, IP6ADDR_FULL), bits);
    return 1;
  case BTRIE_ALLOC_FAILED:
  default:
    return 0;                   /* oom */
  }
}

static void
ds_ip6trie_finish(struct dataset *ds, struct dsctx *dsc)
{
  dsloaded(dsc, "%s", btrie_stats(ds->ds_dsd->btrie));
}

static int
ds_ip6trie_query(const struct dataset *ds, const struct dnsqinfo *qi,
                 struct dnspacket *pkt)
{
  const char *subst = NULL;
  const char *rr;

  if (!qi->qi_ip6valid) return 0;
  check_query_overwrites(qi);

  rr = btrie_lookup(ds->ds_dsd->btrie, qi->qi_ip6, 8 * IP6ADDR_FULL);

  if (!rr)
    return 0;

  if (qi->qi_tflag & NSQUERY_TXT)
    subst = ip6atos(qi->qi_ip6, IP6ADDR_FULL);
  addrr_a_txt(pkt, qi->qi_tflag, rr, subst, ds);
  return NSQUERY_FOUND;
}

#ifndef NO_MASTER_DUMP

/* routines to increment individual bits in ip6 addr: returns carry */
static inline int
increment_bit(ip6oct_t *addr, int bit)
{
  ip6oct_t mask = 1 << (7 - bit % 8);
  if (addr[bit / 8] & mask) {
    addr[bit / 8] &= ~mask;
    return 1;
  } else {
    addr[bit / 8] |= mask;
    return 0;
  }
}

struct dump_context {
  const struct dataset *ds;
  FILE *f;

  ip6oct_t prev_addr[IP6ADDR_FULL];
  const char *prev_rr;

  /* Keep stack of data inherited from parent prefixes */
  const void *parent_data[IP6ADDR_FULL * 8 + 1];
  unsigned depth;
};

static void
dump_cb(const btrie_oct_t *prefix, unsigned len, const void *data, int post,
        void *user_data)
{
  struct dump_context *ctx = user_data;
  unsigned nb = (len + 7) / 8;
  ip6oct_t addr[IP6ADDR_FULL];

  if (nb > IP6ADDR_FULL)
    return;                     /* paranoia */
  /* pad prefix to full ip6 length */
  memcpy(addr, prefix, nb);
  memset(addr + nb, 0, IP6ADDR_FULL - nb);

  if (post == 0) {
    /* pre order visit (before child nodes are visited) */
    /* push the inherited data stack down to our level */
    for (; ctx->depth < len; ctx->depth++)
      ctx->parent_data[ctx->depth + 1] = ctx->parent_data[ctx->depth];
    ctx->parent_data[len] = data;
  }
  else {
    /* post order - restore RR at end of prefix */
    unsigned carry_bits;
    /* increment address to one past the end of the current prefix */
    for (carry_bits = 0; carry_bits < len; carry_bits++)
      if (increment_bit(addr, len - 1 - carry_bits) == 0)
        break;                  /* no carry */
    if (carry_bits == len)
      return;                   /* wrapped - all done */
    /* look up the stack one level for each bit of carry to get
     * the inherited data value at the incremented address */
    ctx->depth = len - 1 - carry_bits;
    data = ctx->parent_data[ctx->depth];
  }

  if (data != ctx->prev_rr) {
    if (memcmp(addr, ctx->prev_addr, IP6ADDR_FULL) != 0) {
      if (ctx->prev_rr)
        dump_ip6range(ctx->prev_addr, addr, ctx->prev_rr, ctx->ds, ctx->f);
      memcpy(ctx->prev_addr, addr, IP6ADDR_FULL);
    }
    /* else addr unchanged => zero-length range, ignore */
    ctx->prev_rr = data;
  }
  /* else rr unchanged => merge current range with previous */
}

static void
ds_ip6trie_dump(const struct dataset *ds,
                const unsigned char UNUSED *unused_odn,
                FILE *f)
{
  struct dump_context ctx;

  memset(&ctx, 0, sizeof(ctx));
  ctx.ds = ds;
  ctx.f = f;
  btrie_walk(ds->ds_dsd->btrie, dump_cb, &ctx);

  /* flush final range */
  if (ctx.prev_rr)
    dump_ip6range(ctx.prev_addr, NULL, ctx.prev_rr, ds, f);
}

#endif
