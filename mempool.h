#ifndef _MEMPOOL_H_INCLUDED
#define _MEMPOOL_H_INCLUDED

struct mempool_chunk;

struct mempool { /* free-once memory pool.  All members are private */
  struct mempool_chunk *mp_chunk; /* list of chunks with free space */
  struct mempool_chunk *mp_fullc; /* list of full chunks */
  unsigned mp_nallocs;		/* number of allocs so far */
  unsigned mp_datasz;		/* size of allocated data */
  const char *mp_laststr;	/* last allocated string */
};

void mp_init(struct mempool *mp);
void *mp_alloc(struct mempool *mp, unsigned size);
void mp_free(struct mempool *mp);
char *mp_strdup(struct mempool *mp, const char *str);
const char *mp_dstrdup(struct mempool *mp, const char *str);
/* dstrdup trying to pack repeated strings together */

#endif
