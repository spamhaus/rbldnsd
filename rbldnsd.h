/* $Id$
 * common rbldnsd #include header
 */

#include <stdarg.h>
#include <sys/types.h>
#include <stdio.h>
#include "ip4addr.h"
#include "dns.h"
#include "mempool.h"

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

extern unsigned char defttl[4];

struct zone;
struct dataset;
struct zonedataset;

struct dnsdnptr {	/* used for DN name compression */
  const unsigned char *dnp;	/* DN pointer */
  unsigned dnlen;		/* length of dnp */
  unsigned qpos;		/* position in query */
};

struct dnsdncompr {	/* dn compression structure */
  struct dnsdnptr ptr[DNS_MAXLABELS];	/* array of pointers */
  struct dnsdnptr *cptr;		/* current (last) pointer */
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
  unsigned q_dnlen;			/* length of qdn */
  unsigned q_dnlab;			/* number of labels in qldn */
  ip4addr_t q_ip4;			/* parsed IP4 address */
  int q_ip4valid;			/* true if q_ip4 is valid */
};

#define skipspace(s) while(*s == ' ' || *s == '\t') ++s
char *parse_uint32(char *s, unsigned char nb[4]);
char *parse_ttl(char *s, unsigned char ttl[4], const unsigned char defttl[4]);
char *parse_dn(char *s, unsigned char *dn, unsigned *dnlenp);

typedef struct dataset *ds_allocfn_t(void);
typedef int ds_loadfn_t(struct zonedataset *zds, FILE *f);
typedef int ds_finishfn_t(struct dataset *ds);
typedef void ds_resetfn_t(struct dataset *ds);
typedef int
ds_queryfn_t(const struct zonedataset *zds, const struct dnsquery *qry,
             struct dnspacket *pkt);

/* use high word so that `generic' dataset works */
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
  ds_resetfn_t *dst_resetfn;	/* routine to release ds internal data */
  const char *dst_descr;    	/* short description of a ds type */
};

/* dst_flags */
#define DSTF_IP4REV	0x01	/* ip4 set */
#define DSTF_ZERODN	0x04	/* query for zero dn too */

#define declaredstype(t) extern const struct dataset_type dataset_##t##_type
#define definedstype(t, flags, descr) \
 static ds_allocfn_t ds_##t##_alloc; \
 static ds_queryfn_t ds_##t##_query; \
 static ds_loadfn_t ds_##t##_load; \
 static ds_finishfn_t ds_##t##_finish; \
 static ds_resetfn_t ds_##t##_reset; \
 const struct dataset_type dataset_##t##_type = { \
   #t, /* name */ flags, \
   ds_##t##_query, ds_##t##_alloc, ds_##t##_load, \
   ds_##t##_finish, ds_##t##_reset, \
   descr }

declaredstype(ip4set);
declaredstype(dnset);
declaredstype(generic);

extern const struct dataset_type *dataset_types[];

/*
 * Each zone is composed of a set of datasets.
 * There is a global list of zonedatas, each
 * with a timestamp etc.
 * Each zonedata is composed of a list of files.
 */

struct zonesoa { /* zsoa */
  int zsoa_valid;		/* true if valid */
  unsigned char zsoa_ttl[4];		/* TTL value */
  unsigned char zsoa_odn[DNS_MAXDN+1];	/* SOA origin DN (len first) */
  unsigned char zsoa_pdn[DNS_MAXDN+1];	/* SOA person DN (len first) */
  unsigned char zsoa_n[20];	/* serial, refresh, retry, expire, minttl */
};

struct zonens { /* zns */
  struct zonens *zns_next;	/* next pointer in the list */
  unsigned char *zns_dn;	/* domain name of a nameserver */
    /* first 4 bytes in zns_ds are TTL value;
     * next is length of DN;
     * rest is DN itself
     */
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
  struct zonens *zds_zns;		/* NS records */
  unsigned char zds_ttl[4];		/* default ttl for a dataset */
  char *zds_subst[10];			/* substitution variables */
  struct mempool zds_mp;		/* memory pool for all data */
  struct zonedataset *zds_next;		/* next in global list */
};

struct zonedatalist {	/* zdl */
  struct zonedataset *zdl_zds;
  ds_queryfn_t *zdl_queryfn;	/* cached from zds */
  struct zonedatalist *zdl_next;
};

struct zone {	/* zone, list of zones */
  char *z_name;				/* name of the zone */
  time_t z_stamp;			/* timestamp, 0 if not loaded */
  unsigned char *z_dn;			/* zone domain name */
  unsigned z_dnlen;			/* length of z_dn[] */
  unsigned z_dnlab;			/* number of dn labels */
  unsigned z_dstflags;			/* flags of all datasets */
  struct zonedatalist *z_zdl;		/* list of datas */
  struct zonesoa z_zsoa;		/* SOA record */
  const unsigned char *z_zns[20];	/* list of nameservers */
    /* keep z_zns definition in sync with rbldnsd_packet.c:addrr_ns() */
  unsigned z_nns;			/* number of nameservers */
  struct zone *z_next;			/* next in list */
};

/* parse query and construct a reply to it, return len of answer or 0 */
int replypacket(struct dnspacket *p, unsigned qlen, const struct zone *zone);
/* log a reply */
struct sockaddr;
void logreply(const struct dnspacket *pkt,
              const struct sockaddr *peeraddr, int peeraddrlen,
              FILE *flog, int flushlog);

/* details of DNS packet structure are in rbldnsd_packet.c */

/* add a record into answer section */
void addrr_a_txt(struct dnspacket *pkt, unsigned qtflag,
                 const char *rr, const char *subst,
                 const struct zonedataset *zds);
void addrr_any(struct dnspacket *pkt, unsigned dtp,
               const void *data, unsigned dsz,
               const unsigned char ttl[4]);
void addrr_mx(struct dnspacket *pkt,
              const unsigned char pri[2],
              const unsigned char *mxdn, unsigned mxdnlen,
              const unsigned char ttl[4]);

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

void PRINTFLIKE(3,4) dslog(int level, int lineno, const char *fmt, ...);
void PRINTFLIKE(2,3) dswarn(int lineno, const char *fmt, ...);
void PRINTFLIKE(1,2) dsloaded(const char *fmt, ...);

int
readdslines(FILE *f, struct zonedataset *zds,
            int (*dslpfn)(struct zonedataset *zds, char *line, int lineno));
/* parse $SPECIAL */
int zds_special(struct zonedataset *zds, char *line);

extern const char def_rr[5];

/* parse line in form :ip:text into rr
 * where first 4 bytes is ip in network byte order.
 * Note this routine uses 4 bytes BEFORE str (it's safe to call it after
 * readdslines() */
int parse_a_txt(char *str, const char **rrp, const char def_a[4]);

/* parse a DN as reverse-octet IP4 address.  return true if ok */
int dntoip4addr(const unsigned char *q, ip4addr_t *ap);

/* the same as in ip4addr, but with error/policy checking */
unsigned ip4parse_cidr(const char *s, ip4addr_t *ap, char **np);
int ip4parse_range(const char *s, ip4addr_t *a1p, ip4addr_t *a2p, char **np);

void oom();
char *emalloc(unsigned size);
char *ezalloc(unsigned size); /* zero-fill */
char *erealloc(void *ptr, unsigned size);
char *estrdup(const char *str);
char *ememdup(const void *buf, unsigned size);

#define tmalloc(type) ((type*)emalloc(sizeof(type)))
#define tzalloc(type) ((type*)ezalloc(sizeof(type)))
#define trealloc(type,ptr,n) ((type*)erealloc((ptr),(n)*(sizeof(type))))

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

/* helper macro to test whenever two given RRs (A and TXT) are equal,
 * provided that arr is zero, this is an exclusion entry.
 *  if arr is zero, we're treating them equal.
 *   else compare pointers
 *   else memcmp first 4 (A) bytes and strcmp rest (TXT)
 */
#define rrs_equal(a, b) \
  (!(a).rr \
   || (a).rr == (b).rr \
   || (memcmp((a).rr, (b).rr, 4) == 0 \
       && strcmp((a).rr + 4, (b).rr + 4) == 0 \
      ) \
  )

