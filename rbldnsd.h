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

extern u_int32_t defttl_nbo;

struct zone;
struct dataset;
struct zonedataset;

struct dnsdnptr {	/* used for DN name compression */
  const unsigned char *dnp;	/* DN pointer */
  unsigned dnlen;		/* length of dnp */
  unsigned qpos;		/* position in query */
};

struct dnsdncompr {
  struct dnsdnptr ptr[DNS_MAXLABELS];	/* array of pointers */
  struct dnsdnptr *cptr;		/* current (last) pointer */
  unsigned char dnbuf[1024];		/* buffer for saved domain names */
  unsigned char *cdnp;			/* current (last) position in dnbuf */
};

struct dnspacket {		/* private structure */
  unsigned char p_buf[DNS_MAXPACKET]; /* packet buffer */
  unsigned char *p_cur;		/* current pointer */
  unsigned char *p_sans;	/* start of answers */
  struct dnsdncompr p_dncompr;	/* DN compression state */
};

struct dnsquery {	/* q */
  unsigned q_type;			/* query RR type */
  unsigned q_class;			/* query class */
  unsigned q_tflag;			/* query RR type flag (NSQUERY_XX) */
  unsigned char q_dn[DNS_MAXDN];	/* original query DN, lowercased */
  unsigned char q_rdn_b[DNS_MAXDN];	/* reverse of q_dn - buffer */
  unsigned char *q_rdn;			/* pointer into q_rdn_b */
  unsigned q_dnlen;			/* length of qdn */
  unsigned q_dnlab;			/* number of labels in qldn */
  ip4addr_t q_ip4;			/* parsed IP4 address */
  unsigned q_ip4oct;			/* number of valid octets in ip4 */
};

#define skipspace(s) while(*s == ' ' || *s == '\t') ++s
char *parse_uint32(unsigned char *s, u_int32_t *np);
char *parse_dn(char *s, unsigned char *dn, unsigned *dnlenp);

typedef struct dataset *ds_allocfn_t(void);
typedef int ds_loadfn_t(struct zonedataset *zds, FILE *f);
typedef int ds_finishfn_t(struct dataset *ds);
typedef void ds_freefn_t(struct dataset *ds);
typedef int
ds_queryfn_t(const struct dataset *ds, const struct dnsquery *query,
             struct dnspacket *packet);

/* flags used in qtyp. should be in MS word for `generic' dataset to work */
#define NSQUERY_TXT	(1u<<16)
#define NSQUERY_A	(1u<<17)
#define NSQUERY_NS	(1u<<18)
#define NSQUERY_SOA	(1u<<19)
#define NSQUERY_MX	(1u<<20)
#define NSQUERY_OTHER	(1u<<31)
#define NSQUERY_ANY	0xffff0000u

struct dataset_type {	/* dst */
  const char *dst_name;		/* name of the type */
  unsigned dst_flags;		/* how to pass arguments to queryfn */
  ds_queryfn_t *dst_queryfn;	/* routine to perform query */
  ds_allocfn_t *dst_allocfn;	/* allocation routine */
  ds_loadfn_t *dst_loadfn;	/* routine to load ds data */
  ds_finishfn_t *dst_finishfn;	/* finish loading */
  ds_freefn_t *dst_freefn;	/* routine to free ds data */
  const char *dst_descr;    	/* short description of a ds type */
};

/* dst_flags */
#define DSTF_IP4REV	0x01	/* ip4 set */
#define DSTF_DNREV	0x02	/* reverse query DN */

#define declaredstype(t) extern const struct dataset_type dataset_##t##_type
#define definedstype(t, flags, descr) \
 static ds_allocfn_t ds_##t##_alloc; \
 static ds_queryfn_t ds_##t##_query; \
 static ds_loadfn_t ds_##t##_load; \
 static ds_finishfn_t ds_##t##_finish; \
 static ds_freefn_t ds_##t##_free; \
 const struct dataset_type dataset_##t##_type = { \
   #t, /* name */ flags, \
   ds_##t##_query, ds_##t##_alloc, ds_##t##_load, \
   ds_##t##_finish, ds_##t##_free, \
   descr }

declaredstype(ip4set);
declaredstype(ip4vset);
declaredstype(dnset);
declaredstype(dnvset);
declaredstype(generic);

/*
 * Each zone is composed of a set of datasets.
 * There is a global list of zonedatas, each
 * with a timestamp etc.
 * Each zonedata is composed of a list of files.
 */

struct zonesoa { /* zsoa */
  int zsoa_valid;		/* true if valid */
  unsigned char zsoa_odn[DNS_MAXDN+1];	/* SOA origin DN (len first) */
  unsigned char zsoa_pdn[DNS_MAXDN+1];	/* SOA person DN (len first) */
  unsigned char zsoa_n[20];	/* serial, refresh, retry, expire, minttl */
};

struct zonens { /* zns */
  struct zonens *zns_next;	/* next pointer in the list */
  unsigned char *zns_dn;	/* domain name of a nameserver */
};

struct zonefile {	/* zf */
  time_t zf_stamp;		/* last timestamp of this file */
  struct zonefile *zf_next;	/* next file in list */
  const char *zf_name;		/* name of this file */
};

struct zonedataset {	/* zds */
  const struct dataset_type *zds_type;	/* type of this data */
  struct dataset *zds_ds;		/* type-specific data */
  time_t zds_stamp;			/* timestamp */
  const char *zds_spec;			/* original specification */
  struct zonefile *zds_zf;		/* list of files for this data */
  struct zonesoa zds_zsoa;		/* SOA record */
  struct zonens *zds_ns;		/* NS records */
  struct zonedataset *zds_next;		/* next in global list */
};

struct zonedatalist {	/* zdl */
  struct zonedataset *zdl_zds;
  struct dataset *zdl_ds;	/* cached from zds */
  ds_queryfn_t *zdl_queryfn;	/* cached from zds */
  struct zonedatalist *zdl_next;
};

struct zone {	/* zone, list of zones */
  char *z_name;				/* name of the zone */
  time_t z_stamp;			/* timestamp, 0 if not loaded */
  unsigned char *z_dn;			/* zone domain name */
  unsigned char *z_rdn;			/* reverse domain name */
  unsigned z_dnlen;			/* length of z_dnr[] */
  unsigned z_dnlab;			/* number of dnr labels */
  unsigned z_dstflags;			/* flags of all datasets */
  struct zonedatalist *z_zdl;		/* list of datas */
  struct zonesoa z_zsoa;		/* SOA record */
  struct zonens *z_zns;			/* list of NS records */
  struct zone *z_next;			/* next in list */
};

/* parse query and construct a reply to it, return len of answer or 0 */
int replypacket(struct dnspacket *p, unsigned qlen, const struct zone *zone);
/* log a reply */
void logreply(const struct dnspacket *pkt, const char *ip,
              FILE *flog, int flushlog);

/* details of DNS packet structure are in rbldnsd_packet.c */

/* add a record into answer section */
int addrec_a(struct dnspacket *p, ip4addr_t aip);
int addrec_txt(struct dnspacket *p, const char *txt, const char *subst);
int addrec_any(struct dnspacket *p, unsigned dtp,
               const void *data, unsigned dsz);
int addrec_ns(struct dnspacket *p,
              const unsigned char *nsdn, unsigned nsdnlen);
int addrec_mx(struct dnspacket *p, const unsigned char prio[2],
              const unsigned char *mxdn, unsigned mxdnlen);

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

struct zone *addzone(struct zone *zonelist, const char *spec);
int reloadzones(struct zone *zonelist);
void printdstypes(FILE *f);

void PRINTFLIKE(3,4) dslog(int level, int lineno, const char *fmt, ...);
void PRINTFLIKE(2,3) dswarn(int lineno, const char *fmt, ...);
void PRINTFLIKE(1,2) dsloaded(const char *fmt, ...);

#define R_A_DEFAULT ((ip4addr_t)0x7f000002)

int
readdslines(FILE *f, struct zonedataset *zds,
            int (*dslpfn)(struct dataset *ds, char *line, int lineno));

/* parse a DN as reverse-octet IP4 address.  Return number of octets
 * (1..4) or 0 in case q isn't a valid IP4 address. */
unsigned dntoip4addr(const unsigned char *q, ip4addr_t *ap);

/* the same as in ip4addr, but with error/policy checking */
unsigned ip4parse_cidr(const char *s, ip4addr_t *ap, char **np);
int ip4parse_range(const char *s, ip4addr_t *a1p, ip4addr_t *a2p, char **np);

int addrtxt(char *str, ip4addr_t *ap, char **txtp);

void oom();
void *emalloc(unsigned size);
void *ezalloc(unsigned size); /* zero-fill */
void *erealloc(void *ptr, unsigned size);
char *estrdup(const char *str);

#define tmalloc(type) ((type*)emalloc(sizeof(type)))
#define tzalloc(type) ((type*)ezalloc(sizeof(type)))
#define trealloc(type,ptr,n) ((type*)erealloc((ptr),(n)*(sizeof(type))))

struct mempool;
void *mp_ealloc(struct mempool *mp, unsigned size);
char *mp_estrdup(struct mempool *mp, const char *str);
void *mp_ememdup(struct mempool *mp, const void *buf, unsigned len);
const char *mp_edstrdup(struct mempool *mp, const char *str);
const void *mp_edmemdup(struct mempool *mp, const void *buf, unsigned len);

int vssprintf(char *buf, int bufsz, const char *fmt, va_list ap);
int PRINTFLIKE(3, 4) ssprintf(char *buf, int bufsz, const char *fmt, ...);

/* a helper to shrink an array */
#define SHRINK_ARRAY(type, arr, needed, allocated)	\
  if ((allocated) > (needed)) {				\
     (arr) = trealloc(type, (arr), (needed));		\
     (allocated) = (needed);				\
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


