/* ip4trie dataset type: IP4 CIDR ranges with A and TXT values.
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

definedstype(ip4trie, DSTF_IP4REV, "set of (ip4cidr, value) pairs");

static void ds_ip4trie_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  memset(dsd, 0, sizeof(*dsd));
}

static void ds_ip4trie_start(struct dataset *ds) {
  struct dsdata *dsd = ds->ds_dsd;

  dsd->def_rr = def_rr;
  if (!dsd->btrie)
    dsd->btrie = btrie_init(ds->ds_mp);
}

static int
ds_ip4trie_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  ip4addr_t a;
  btrie_oct_t addr_bytes[4];
  int bits;
  const char *rr;
  unsigned rrl;

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
  if ((bits = ip4cidr(s, &a, &s)) < 0 ||
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
    rr = NULL;
  else {
    SKIPSPACE(s);
    if (!*s || ISCOMMENT(*s))
      rr = dsd->def_rr;
    else if (!(rrl = parse_a_txt(s, &rr, dsd->def_rr, dsc)))
      return 1;
    else if (!(rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
  }

  ip4unpack(addr_bytes, a);
  switch(btrie_add_prefix(dsd->btrie, addr_bytes, bits, rr)) {
  case BTRIE_OKAY:
    return 1;
  case BTRIE_DUPLICATE_PREFIX:
    dswarn(dsc, "duplicated entry for %s/%d", ip4atos(a), bits);
    return 1;
  case BTRIE_ALLOC_FAILED:
  default:
    return 0;                   /* oom */
  }
}

static void ds_ip4trie_finish(struct dataset *ds, struct dsctx *dsc) {
  dsloaded(dsc, "%s", btrie_stats(ds->ds_dsd->btrie));
}

static int
ds_ip4trie_query(const struct dataset *ds, const struct dnsqinfo *qi,
                 struct dnspacket *pkt) {
  const char *rr;
  btrie_oct_t addr_bytes[4];

  if (!qi->qi_ip4valid) return 0;
  check_query_overwrites(qi);

  ip4unpack(addr_bytes, qi->qi_ip4);
  rr = btrie_lookup(ds->ds_dsd->btrie, addr_bytes, 32);

  if (!rr)
    return 0;

  addrr_a_txt(pkt, qi->qi_tflag, rr,
              qi->qi_tflag & NSQUERY_TXT ? ip4atos(qi->qi_ip4) : NULL, ds);
  return NSQUERY_FOUND;
}

#ifndef NO_MASTER_DUMP

static inline int
increment_bit(ip4addr_t *addr, int bit)
{
  ip4addr_t mask = (ip4addr_t)1 << (31 - bit);
  if (*addr & mask) {
    *addr &= ~mask;
    return 1;
  } else {
    *addr |= mask;
    return 0;
  }
}

struct dump_context {
  const struct dataset *ds;
  FILE *f;

  ip4addr_t prev_addr;
  const char *prev_rr;

  /* Keep stack of data inherited from parent prefixes */
  const void *parent_data[33];
  unsigned depth;
};

static void
dump_cb(const btrie_oct_t *prefix, unsigned len, const void *data, int post,
        void *user_data)
{
  struct dump_context *ctx = user_data;
  ip4addr_t addr;

  if (len > 32)
    return;                     /* paranoia */
  addr = (prefix[0] << 24) + (prefix[1] << 16) + (prefix[2] << 8) + prefix[3];
  addr &= len ? -((ip4addr_t)1 << (32 - len)) : 0;

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
      if (increment_bit(&addr, len - 1 - carry_bits) == 0)
        break;                  /* no carry */
    if (carry_bits == len)
      return;                   /* wrapped - all done */
    /* look up the stack one level for each bit of carry to get
     * the inherited data value at the incremented address */
    ctx->depth = len - 1 - carry_bits;
    data = ctx->parent_data[ctx->depth];
  }

  if (data != ctx->prev_rr) {
    if (addr != ctx->prev_addr) {
      if (ctx->prev_rr)
        dump_ip4range(ctx->prev_addr, addr - 1, ctx->prev_rr, ctx->ds, ctx->f);
      ctx->prev_addr = addr;
    }
    /* else addr unchanged => zero-length range, ignore */
    ctx->prev_rr = data;
  }
  /* else rr unchanged => merge current range with previous */
}

static void
ds_ip4trie_dump(const struct dataset *ds,
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
    dump_ip4range(ctx.prev_addr, ip4mask(32), ctx.prev_rr, ds, f);
}

#endif
