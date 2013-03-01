/* memory pool implementation
 */

#include <stdlib.h>
#include <string.h>
#include "mempool.h"

/* A pool of constant (in size) memory blocks which will be
 * freed all at once.  We allocate memory in (relatively)
 * large chunks (MEMPOOL_CHUNKSIZE) and keep list of chunks
 * with some free space within them and list of chunks without
 * sufficient free space.  Mempool is optimized to allocate
 * blocks of approximate equal size (determined dynamically),
 * so free chunks are moved to "used" list when free space
 * becomes less than an average allocated block size.
 */

#define alignto sizeof(void*)
#define alignmask (alignto-1)

void *emalloc(unsigned size);

#define MEMPOOL_CHUNKSIZE (65536-sizeof(unsigned)*4)

struct mempool_chunk {
  char buf[MEMPOOL_CHUNKSIZE+alignto];
  struct mempool_chunk *next;
  unsigned size;
};

struct mempool_cfull { /* pseudo-chunk: one entry into full list */
  struct mempool_chunk *next;
  char buf[1];
};

void mp_init(struct mempool *mp) {
  mp->mp_chunk = mp->mp_fullc = NULL;
  mp->mp_nallocs = mp->mp_datasz = 0;
  mp->mp_lastbuf = NULL;
  mp->mp_lastlen = 0;
}

void *mp_alloc(struct mempool *mp, unsigned size, int align) {
  if (size >= MEMPOOL_CHUNKSIZE / 2) {
    /* for large blocks, allocate separate "full" chunk */
    struct mempool_cfull *c =
      (struct mempool_cfull*)emalloc(sizeof(*c)+size-1);
    if (!c)
      return NULL;
    c->next = mp->mp_fullc;
    mp->mp_fullc = (struct mempool_chunk*)c;
    return c->buf;
  }
  else {
    struct mempool_chunk *c;
    struct mempool_chunk *best; /* "best fit" chunk */
    unsigned avg; /* average data size: total size / numallocs */

    ++mp->mp_nallocs; mp->mp_datasz += size;
    avg = mp->mp_datasz / mp->mp_nallocs;

    /* round size up to a multiple of alignto */
    if (align)
      size = (size + alignmask) & ~alignmask;

    for(c = mp->mp_chunk, best = NULL; c; c = c->next)
      if (c->size >= size && (!best || best->size > c->size)) {
        best = c;
        if (c->size - size < avg)
          break;
      }
    
    if (best != NULL) { /* found a free chunk */
      char *b;
      if (align)
        best->size &= ~alignmask;
      b = best->buf + MEMPOOL_CHUNKSIZE - best->size;
      best->size -= size;
      if (best->size < avg) {
        struct mempool_chunk **cp = &mp->mp_chunk;
        while(*cp != best)
          cp = &(*cp)->next;
        *cp = best->next;
        best->next = mp->mp_fullc;
        mp->mp_fullc = best;
      }
      return b;
    }

    else { /* no sutable chunks -> allocate new one */
      c = (struct mempool_chunk *)emalloc(sizeof(*c));
      if (!c)
        return NULL;
      c->next = mp->mp_chunk;
      mp->mp_chunk = c;
      c->size = MEMPOOL_CHUNKSIZE - size;
      return c->buf;
    }
  }
}

void mp_free(struct mempool *mp) {
  struct mempool_chunk *c;
  while((c = mp->mp_chunk) != NULL) {
    mp->mp_chunk = c->next;
    free(c);
  }
  while((c = mp->mp_fullc) != NULL) {
    mp->mp_fullc = c->next;
    free(c);
  }
  mp_init(mp);
}

void *mp_memdup(struct mempool *mp, const void *buf, unsigned len) {
  void *b = mp_alloc(mp, len, 0);
  if (b)
    memcpy(b, buf, len);
  return b;
}

char *mp_strdup(struct mempool *mp, const char *str) {
  return (char*)mp_memdup(mp, str, strlen(str) + 1);
}

/* string pool: a pool of _constant_ strings, with minimal
 * elimination of dups (only last request is checked)
 */

const void *mp_dmemdup(struct mempool *mp, const void *buf, unsigned len) {
  if (mp->mp_lastlen == len && memcmp(mp->mp_lastbuf, buf, len) == 0)
    return mp->mp_lastbuf;
  else if ((buf = mp_memdup(mp, buf, len)) != NULL)
    mp->mp_lastbuf = buf, mp->mp_lastlen = len;
  return buf;
}

const char *mp_dstrdup(struct mempool *mp, const char *str) {
  return (const char*)mp_dmemdup(mp, str, strlen(str) + 1);
}
