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

void oom();

#define MEMPOOL_CHUNKSIZE (65536-sizeof(unsigned)*3)

struct mempool_chunk {
  struct mempool_chunk *next;
  unsigned size;
  char buf[MEMPOOL_CHUNKSIZE];
};

struct mempool_cfull { /* pseudo-chunk: one entry into full list */
  struct mempool_chunk *next;
  char buf[1];
};

void mp_init(struct mempool *mp) {
  mp->mp_chunk = mp->mp_fullc = NULL;
  mp->mp_nallocs = mp->mp_datasz = 0;
  mp->mp_laststr = NULL;
}

void *mp_alloc(struct mempool *mp, unsigned size) {
  if (size >= MEMPOOL_CHUNKSIZE / 2) {
    /* for large blocks, allocate separate "full" chunk */
    struct mempool_cfull *c =
      (struct mempool_cfull*)malloc(sizeof(*c)+size-1);
    if (!c) {
      oom();
      return NULL;
    }
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

    for(c = mp->mp_chunk, best = NULL; c; c = c->next)
      if (c->size >= size && (!best || best->size > c->size)) {
        best = c;
        if (c->size - size < avg)
          break;
      }
    
    if (best != NULL) { /* found a free chunk */
      char *b = best->buf + MEMPOOL_CHUNKSIZE - best->size;
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
      c = (struct mempool_chunk *)malloc(sizeof(*c));
      if (!c) {
        oom();
        return NULL;
      }
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

char *mp_strdup(struct mempool *mp, const char *str) {
  unsigned l = strlen(str) + 1;
  char *s = (char*)mp_alloc(mp, l);
  if (s)
    memcpy(s, str, l);
  return s;
}

/* string pool: a pool of _constant_ strings, with minimal
 * elimination of dups (only last request is checked)
 */

const char *mp_dstrdup(struct mempool *mp, const char *str) {
  if (mp->mp_laststr && strcmp(mp->mp_laststr, str) == 0)
    return mp->mp_laststr;
  else if ((str = mp_strdup(mp, str)) != NULL)
    mp->mp_laststr = str;
  return str;
}   
