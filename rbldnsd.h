/* $Id$
 * common rbldnsd #include header
 */

#include <stdarg.h>
#include <sys/types.h>
#include <stdio.h>
#include "ip4addr.h"
#include "dns.h"

#if !defined(__GNUC__) && !defined(__attribute__)
# define __attribute__(x)
#endif
#ifndef PRINTFLIKE
# define PRINTFLIKE(fmtp, ap) __attribute__((format(printf,fmtp,ap)))
#endif
#ifndef UNUSED
# define UNUSED __attribute__((unused))
#endif
#ifndef NORETURN
# define NORETURN __attribute__((noreturn))
#endif

extern char *progname; /* limited to 32 chars */
extern int logto;
#define LOGTO_STDOUT 0x01
#define LOGTO_SYSLOG 0x02
void PRINTFLIKE(2,3) NORETURN error(int errnum, const char *fmt, ...);

extern unsigned defttl;

struct zone;
struct zonetype;
struct zonedata;

struct dnspacket {		/* private structure */
  unsigned char p[DNS_MAXPACKET]; /* packet buffer */
  unsigned char *c;		/* current pointer */
  unsigned char *sans;		/* start of answers */
  unsigned nans;		/* number of answers */
};

/* parse query and construct a reply to it, return len of answer or 0 */
int replypacket(struct dnspacket *p, unsigned qlen, const struct zone *zone);
/* log a reply */
void logreply(const struct dnspacket *pkt, const char *ip, FILE *flog);

/* details of DNS packet structure are in rbldnsd_packet.c */
int addrec_a(struct dnspacket *p, ip4addr_t aip);
int addrec_txt(struct dnspacket *p, const char *txt, const char *subst);
int addrec_any(struct dnspacket *p, unsigned dtp,
               const void *data, unsigned dsz);


struct dnsstats {
  time_t stime;			/* start time */
  /* n - number of requests;
   * i - number of bytes read
   * o - number of bytes written
   * a - number of answers */
  unsigned nbad, ibad;			/* unrecognized, short etc requests */
  unsigned nnxd, inxd, onxd;		/* NXDOMAINs */
  unsigned nrep, irep, orep, arep;	/* OK replies */
  unsigned nerr, ierr, oerr;		/* other errors (REFUSED, FORMERR...) */
};

struct zone *addzone(struct zone *zlist, const char *spec);
int reloadzones(struct zone *zl);
void printzonetypes(FILE *f);

void PRINTFLIKE(3,4) zlog(int level, int lineno, const char *fmt, ...);
void PRINTFLIKE(2,3) zwarn(int lineno, const char *fmt, ...);
void PRINTFLIKE(1,2) zloaded(const char *fmt, ...);

#define R_A_DEFAULT ((ip4addr_t)0x7f000002)

typedef struct zonedata *z_allocfn(void);
typedef int z_loadfn(struct zonedata *z, FILE *f);
typedef int z_finishfn(struct zonedata *z);
typedef void z_freefn(struct zonedata *z);
typedef int
z_queryfn(const struct zonedata *const zone, struct dnspacket *p,
          const unsigned char *const query, unsigned qlevels, unsigned qtyp);

/* flags used in qtyp */
#define NSQUERY_TXT	(1u<< 8)
#define NSQUERY_A	(1u<< 9)
#define NSQUERY_NS	(1u<<10)
#define NSQUERY_SOA	(1u<<11)
#define NSQUERY_OTHER	(1u<<12)

#define NSQUERY_A_TXT	(NSQUERY_A|NSQUERY_TXT)
#define NSQUERY_ANY	0xff00u

struct zonetype {
  const char *name;     /* name of the type */
  unsigned qfilter;	/* which records we recognize */
  z_queryfn *queryfn;   /* routine to perform query */
  z_allocfn *allocfn;	/* allocation routine */
  z_loadfn *loadfn;     /* routine to load zone data */
  z_finishfn *finishfn;	/* finish loading */
  z_freefn *freefn;     /* routine to free zone data */
  const char *descr;    /* short description of a zone type */
};

#define declarezonetype(t) extern const struct zonetype t##_zone
#define definezonetype(t, qfilter, descr) \
 static z_allocfn t##_alloc; \
 static z_queryfn t##_query; \
 static z_loadfn t##_load; \
 static z_finishfn t##_finish; \
 static z_freefn t##_free; \
 const struct zonetype t##_zone = { \
   #t, /* name */ qfilter, \
   t##_query, t##_alloc, t##_load, t##_finish, t##_free, \
   descr }

declarezonetype(ip4set);
declarezonetype(ip4vset);
declarezonetype(dnset);
declarezonetype(dnvset);
declarezonetype(generic);

int
readzlines(FILE *f, struct zonedata *z,
           int (*zlpfn)(struct zonedata *z,
                        char *line, int lineno, int llines));

ip4addr_t dntoip4addr(const unsigned char *q);

/* the same as in ip4addr, but with error/policy checking */
unsigned ip4parse_cidr(const char *s, ip4addr_t *ap, char **np);
int ip4parse_range(const char *s, ip4addr_t *a1p, ip4addr_t *a2p, char **np);

int addrtxt(char *str, ip4addr_t *ap, char **txtp);

void oom();
void *emalloc(unsigned size);
void *erealloc(void *ptr, unsigned size);
char *estrdup(const char *str);
struct mempool;
void *mp_ealloc(struct mempool *mp, unsigned size);
char *mp_estrdup(struct mempool *mp, const char *str);
const char *mp_edstrdup(struct mempool *mp, const char *str);

int vssprintf(char *buf, int bufsz, const char *fmt, va_list ap);
int PRINTFLIKE(3, 4) ssprintf(char *buf, int bufsz, const char *fmt, ...);

/* a helper to shrink an array */
#define SHRINK_ARRAY(type, arr, needed, allocated)		\
  if ((allocated) > (needed)) {					\
     (arr) = (type*)realloc((arr), (needed) * sizeof(type));	\
     (allocated) = (needed);					\
  }

/* a helper macro to remove dups from a sorted array */

#define REMOVE_DUPS(type, arr, num, eq)	\
{ register type *_p, *_e, *_t;		\
  _p = arr; _t = _p + num - 1;		\
  while(_p < _t)			\
    if (!(eq((_p[0]), (_p[1])))) ++_p;	\
    else {				\
      ++_t; _e = _p + 1;		\
      do				\
        if (eq((*_p), (*_e))) ++_e;	\
        else *++_p = *_e++;		\
      while (_e < _t);			\
      num = _p + 1 - arr;		\
      break;				\
    }					\
}

/* helper macro to test whenever two given entries
 * with r_a and r_txt fields, are equal, provided
 * that if r_a is zero, this is an exclusion entry.
 *  if a's r_a is zero, we're treating them equal.
 *   if r_a's are equal,
 *    if a.r_txt is non-null
 *      if b.r_txt is non-null
 *        strcmp
 *      else not eq
 *    else if b.r_txt is non-null -> not eq
 *    else eq
 */
#define rrs_equal(a, b) \
  (!(a).r_a \
   || ((a).r_a == (b).r_a \
       && ((a).r_txt \
             ? ((b).r_txt \
                  ? strcmp((a).r_txt, (b).r_txt) == 0 \
                  : 0 \
               ) \
             : ((b).r_txt ? 0 : 1) \
          ) \
      ) \
  )


/* helper macro for ip4range_expand:
 * deal with last octet, shifting a and b when done
 */
#define _ip4range_expand_octet(a,b,fn,bits)		\
  if ((a | 255u) >= b) {				\
    if ((a ^ b) == 255u)				\
      return fn((bits>>3)+1, a<<bits, 1);		\
    else						\
      return fn(bits>>3, a<<bits, b - a + 1);		\
  }							\
  if (a & 255u) {					\
    if (!fn(bits>>3, a<<bits, 256u - (a & 255u)))	\
      return 0;						\
    a = (a >> 8) + 1;					\
  }							\
  else							\
    a >>= 8;						\
  if ((b & 255u) != 255u) {				\
    if (!fn((bits>>3), (b & ~255u)<<bits, (b&255u)+1))	\
      return 0;						\
    b = (b >> 8) - 1;					\
  }							\
  else							\
    b >>= 8

/* ip4range_expand(start,stop,function)
 * "expand" an ip4 range [start,stop] to a set of
 * arrays of /32, /24, /16 and /8 cidr ranges, calling
 * a given function for each array with parameters
 *  int function(idx, start, count):
 *   idx - "index", 0=/32, 1=/24, 2=/16 and 3=/8
 *   start - starting IP address
 *   number of consecutive entries
 * Side effect: ip4range_expand is "terminal routine",
 * that is, it does return from the caller with int
 * result (0/1): if function returns 0, ip4range_expand
 * will return from a caller with code 0, else, when all
 * is done, it will return with 1.
 * This marco is used to convert ip4 ranges to array
 * elements in ip4set and ip4vset types.
 */

#define ip4range_expand(a,b,fn)	{	\
  _ip4range_expand_octet(a,b,fn,0);	\
  _ip4range_expand_octet(a,b,fn,8);	\
  _ip4range_expand_octet(a,b,fn,16);	\
  return fn(3, a << 24, b - a + 1); }

