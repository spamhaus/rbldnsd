/* $Id$
 * common rbldnsd #include header
 */

#include <stdarg.h>
#include <sys/types.h>
#include <stdio.h>
#include "config.h"
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
#define LOGTO_STDERR 0x02
#define LOGTO_SYSLOG 0x04
void PRINTFLIKE(2,3) NORETURN error(int errnum, const char *fmt, ...);

struct zone;
struct dataset;
struct dsdata;

struct dnspacket {		/* private structure */
  unsigned char p_buf[DNS_MAXPACKET]; /* packet buffer */
  unsigned char *p_cur;		/* current pointer */
  unsigned char *p_sans;	/* start of answers */
};

struct dnsquery {	/* q */
  unsigned q_type;			/* query RR type */
  unsigned q_class;			/* query class */
  unsigned char q_dn[DNS_MAXDN];	/* original query DN, lowercased */
  unsigned q_dnlen;			/* length of q_dn */
  unsigned q_dnlab;			/* number of labels in q_dn */
  unsigned char *q_lptr[DNS_MAXLABELS];	/* pointers to labels */
};

struct dnsqinfo {	/* qi */
  unsigned char *const *qi_dnlptr;
  const unsigned char *qi_dn;		/* cached query DN */
  unsigned qi_tflag;			/* query RR type flag (NSQUERY_XX) */
  unsigned qi_dnlen0;			/* length of qi_dn - 1 */
  unsigned qi_dnlab;			/* number of labels in q_dn */
  ip4addr_t qi_ip4;			/* parsed IP4 address */
  int qi_ip4valid;			/* true if qi_ip4 is valid */
};

#define PACK32(b,n) ((b)[0]=(n)>>24,(b)[1]=(n)>>16,(b)[2]=(n)>>8,(b)[3]=(n))
#define PACK32S(b,n) (*b++=(n)>>24,*b++=(n)>>16,*b++=(n)>>8,*b++=n)
#define PACK16(b,n) ((b)[0]=(n)>>8,(b)[1]=(n))
#define PACK16S(b,n) (*b++=(n)>>8,*b++=(n))

unsigned unpack32(const unsigned char nb[4]);

#define ISSPACE(c) ((c) == ' ' || (c) == '\t')
#define ISCOMMENT(c) ((c) == '#' || (c) == ';')
#define SKIPSPACE(s) while(ISSPACE(*s)) ++s

char *parse_uint32(char *s, unsigned *np);
char *parse_uint32_nb(char *s, unsigned char nb[4]);
char *parse_time(char *s, unsigned *tp);
char *parse_time_nb(char *s, unsigned char nb[4]);
char *parse_ttl(char *s, unsigned *ttlp, unsigned defttl);
char *parse_dn(char *s, unsigned char *dn, unsigned *dnlenp);
/* parse line in form :ip:text into rr
 * where first 4 bytes is ip in network byte order.
 * Note this routine uses 4 bytes BEFORE str (it's safe to call it after
 * readdslines() */
int parse_a_txt(int lineno, char *str, const char **rrp, const char def_a[4]);

typedef void ds_startfn_t(struct dataset *ds);
typedef int ds_linefn_t(struct dataset *ds, char *line, int lineno);
typedef void ds_finishfn_t(struct dataset *ds);
typedef void ds_resetfn_t(struct dsdata *dsd, int freeall);
typedef int
ds_queryfn_t(const struct dataset *ds, const struct dnsqinfo *qi,
             struct dnspacket *pkt);
typedef void
ds_dumpfn_t(const struct dataset *ds, const unsigned char *odn, FILE *f);

#define NSQUERY_OTHER	0
#define NSQUERY_SOA	(1u<<0)
#define NSQUERY_NS	(1u<<1)
#define NSQUERY_A	(1u<<2)
#define NSQUERY_MX	(1u<<3)
#define NSQUERY_TXT	(1u<<4)
#define NSQUERY_ANY	0xffffu

struct dstype {	/* dst */
  const char *dst_name;		/* name of the type */
  unsigned dst_flags;		/* how to pass arguments to queryfn */
  unsigned dst_size;		/* size of struct dataset */
  ds_resetfn_t *dst_resetfn;	/* routine to release ds internal data */
  ds_startfn_t *dst_startfn;	/* routine called at start of every file */
  ds_linefn_t *dst_linefn;	/* routine to parse input line */
  ds_finishfn_t *dst_finishfn;	/* finish loading */
  ds_queryfn_t *dst_queryfn;	/* routine to perform query */
  ds_dumpfn_t *dst_dumpfn;	/* dump zone in BIND format */
  const char *dst_descr;    	/* short description of a ds type */
};

/* dst_flags */
#define DSTF_IP4REV	0x01	/* ip4 set */
#define DSTF_ZERODN	0x04	/* query for zero dn too */

#define declaredstype(t) extern const struct dstype dataset_##t##_type
#define definedstype(t, flags, descr) \
 static ds_resetfn_t ds_##t##_reset; \
 static ds_startfn_t ds_##t##_start; \
 static ds_linefn_t ds_##t##_line; \
 static ds_finishfn_t ds_##t##_finish; \
 static ds_queryfn_t ds_##t##_query; \
 static ds_dumpfn_t ds_##t##_dump; \
 const struct dstype dataset_##t##_type = { \
   #t /* name */, flags, sizeof(struct dsdata), \
   ds_##t##_reset, ds_##t##_start, ds_##t##_line, ds_##t##_finish, \
   ds_##t##_query, ds_##t##_dump, \
   descr }

declaredstype(ip4set);
declaredstype(ip4trie);
declaredstype(dnset);
declaredstype(dnhash);
declaredstype(generic);
declaredstype(combined);

extern const struct dstype *ds_types[];

/*
 * Each zone is composed of a set of datasets.
 * There is a global list of datasets, each
 * with a timestamp etc.
 * Each zonedata is composed of a list of files.
 */

struct dsfile {	/* dsf */
  time_t dsf_stamp;		/* last timestamp of this file */
  struct dsfile *dsf_next;	/* next file in list */
  const char *dsf_name;		/* name of this file */
};

struct dssoa { /* dssoa */
  unsigned dssoa_ttl;			/* TTL value */
  const unsigned char *dssoa_odn;	/* origin DN */
  const unsigned char *dssoa_pdn;	/* person DN */
  unsigned dssoa_serial;		/* SOA serial # */
  unsigned char dssoa_n[16];		/* refresh, retry, expire, minttl */
};

struct dsns { /* dsns, nameserver */
  struct dsns *dsns_next;		/* next nameserver in list */
  unsigned char dsns_dn[1];		/* nameserver DN, varlen */
};

struct dataset {	/* ds */
  const struct dstype *ds_type;	/* type of this data */
  struct dsdata *ds_dsd;		/* type-specific data */
  time_t ds_stamp;			/* timestamp */
  const char *ds_spec;			/* original specification */
  struct dsfile *ds_dsf;		/* list of files for this data */
  struct dssoa *ds_dssoa;		/* SOA record */
  struct dsns *ds_dsns;			/* list of nameservers */
  unsigned ds_nsttl;			/* TTL for NS records */
#ifndef INCOMPAT_0_99
  int ds_nsflags;
#define DSF_NEWNS  0x01			/* new-style NS on one line */
#define DSF_NSWARN 0x02			/* warned about new-style NS */
#endif
  unsigned ds_ttl;			/* default ttl for a dataset */
  char *ds_subst[10];			/* substitution variables */
  struct mempool *ds_mp;		/* memory pool for data */
  struct dataset *ds_next;		/* next in global list */
  /* for (re)loads */
  unsigned ds_warn;			/* number of load warnings */
  const char *ds_fname;			/* current file name */
  struct dataset *ds_subset;		/* currently loading subset */
};

struct dslist {	/* dsl */
  struct dataset *dsl_ds;
  ds_queryfn_t *dsl_queryfn;	/* cached dsl_ds->ds_type->dst_queryfn */
  struct dslist *dsl_next;
};

struct zonesoa;
struct zonens;

#if !defined(NOSTDINT_H)
typedef uint64_t dnscnt_t;
#define PRI_DNSCNT PRIu64
#elif SIZEOF_LONG < 8 && defined(SIZEOF_LONG_LONG)
typedef unsigned long long dnscnt_t;
#define PRI_DNSCNT "llu"
#else
typedef unsigned long dnscnt_t;
#define PRI_DNSCNT "lu"
#endif
struct dnsstats {
  /* n - number of requests;
   * i - number of bytes read
   * o - number of bytes written
   */
  dnscnt_t nnxd, inxd, onxd;		/* NXDOMAINs */
  dnscnt_t nrep, irep, orep;		/* OK replies */
  dnscnt_t nerr, ierr, oerr;		/* other errors (REFUSED, FORMERR...) */
};

#define MAX_NS 20

struct zone {	/* zone, list of zones */
  unsigned z_stamp;			/* timestamp, 0 if not loaded */
  unsigned char z_dn[DNS_MAXDN+1];	/* zone domain name */
  unsigned z_dnlen;			/* length of z_dn */
  unsigned z_dnlab;			/* number of dn labels */
  unsigned z_dstflags;			/* flags of all datasets */
  struct dslist *z_dsl;			/* list of datasets */
  struct dslist **z_dslp;		/* last z_dsl in list */
  /* SOA record */
  const struct dssoa *z_dssoa;		/* original SOA from a dataset */
  struct zonesoa *z_zsoa;		/* pre-packed SOA record */
  const unsigned char *z_nsdna[MAX_NS];	/* array of nameserver DNs */
  unsigned z_nns;			/* number of NSes in z_dsnsa[] */
  unsigned z_nsttl;			/* ttl for NS records */
  unsigned z_cns;			/* current NS in rotation */
  struct zonens *z_zns;			/* pre-packed NS records */
#ifndef NOSTATS
  struct dnsstats z_stats;		/* statistic counters */
#endif
  struct zone *z_next;			/* next in list */
};

void init_zones_caches(struct zone *zonelist);
int update_zone_soa(struct zone *zone, const struct dssoa *dssoa);
int update_zone_ns(struct zone *zone, const struct dsns *dsns, unsigned ttl);

/* parse query and construct a reply to it, return len of answer or 0 */
int replypacket(struct dnspacket *p, unsigned qlen, const struct zone *zone,
                struct zone **mzone);
const struct zone *
findqzone(const struct zone *zonelist,
          unsigned dnlen, unsigned dnlab, unsigned char *const *const dnlptr,
          struct dnsqinfo *qi);

/* log a reply */
struct sockaddr;
void logreply(const struct dnspacket *pkt,
              const struct sockaddr *peeraddr, int peeraddrlen,
              FILE *flog, int flushlog);

/* details of DNS packet structure are in rbldnsd_packet.c */

/* add a record into answer section */
void addrr_a_txt(struct dnspacket *pkt, unsigned qtflag,
                 const char *rr, const char *subst,
                 const struct dataset *ds);
void addrr_any(struct dnspacket *pkt, unsigned dtp,
               const void *data, unsigned dsz, unsigned ttl);
void dump_a_txt(const char *name, const unsigned char *rr,
                const char *subst, const struct dataset *ds, FILE *f);

struct zone *addzone(struct zone *zonelist, const char *spec);
void connectdataset(struct zone *zone,
                    struct dataset *ds,
                    struct dslist *dsl);
struct zone *newzone(struct zone **zonelist,
                     unsigned char *dn, unsigned dnlen,
                     struct mempool *mp);
int reloadzones(struct zone *zonelist);
void dumpzone(const struct zone *z, FILE *f);

void PRINTFLIKE(3,4) dslog(int level, int lineno, const char *fmt, ...);
void PRINTFLIKE(2,3) dswarn(int lineno, const char *fmt, ...);
void PRINTFLIKE(1,2) dsloaded(const char *fmt, ...);
extern struct dataset *ds_loading;
void PRINTFLIKE(3,4)
zlog(int level, const struct zone *zone, const char *fmt, ...);

int readdslines(FILE *f, struct dataset *ds);
/* parse $SPECIAL */
int ds_special(struct dataset *ds, char *line, int lineno);

/* from rbldnsd_combined.c, special routine used inside ds_special() */
int ds_combined_newset(struct dataset *ds, char *line, int lineno);

extern unsigned def_ttl;
extern const char def_rr[5];

extern const char *show_version; /* version.bind CH TXT */

/* the same as in ip4addr, but with error/policy checking */
unsigned ip4parse_cidr(const char *s, ip4addr_t *ap, char **np);
int ip4parse_range(const char *s, ip4addr_t *a1p, ip4addr_t *a2p, char **np);

void oom(void);
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

