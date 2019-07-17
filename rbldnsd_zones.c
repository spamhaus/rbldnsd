/* Nameserver zones: structures and routines
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "rbldnsd.h"
#include "istream.h"

static struct dataset *ds_list;
struct dataset *g_dsacl;

static struct dataset *newdataset(char *spec) {
  /* type:file,file,file... */
  struct dataset *ds, **dsp;
  char *f;
  struct dsfile **dsfp, *dsf;
  static const char *const delims = ",:";
  const struct dstype **dstp;

  f = strchr(spec, ':');
  if (!f)
    error(0, "invalid zone data specification `%.60s'", spec);
  *f++ = '\0';

  for(dsp = &ds_list; (ds = *dsp) != NULL; dsp = &ds->ds_next)
    if (strcmp(ds->ds_type->dst_name, spec) == 0 &&
        strcmp(ds->ds_spec, f) == 0)
      return ds;

  dstp = ds_types;
  while(strcmp(spec, (*dstp)->dst_name))
    if (!*++dstp)
      error(0, "unknown dataset type `%.60s'", spec);
  ds = (struct dataset*)ezalloc(sizeof(struct dataset) +
                                     sizeof(struct mempool) +
                                     (*dstp)->dst_size);
  ds->ds_type = *dstp;
  ds->ds_mp = (struct mempool*)(ds + 1);
  ds->ds_dsd = (struct dsdata*)(ds->ds_mp + 1);
  ds->ds_spec = estrdup(f);

  ds->ds_next = NULL;
  *dsp = ds;

  dsfp = &ds->ds_dsf;
  for (f = strtok(f, delims); f; f = strtok(NULL, delims)) {
    dsf = tmalloc(struct dsfile);
    dsf->dsf_stamp = 0;
    dsf->dsf_name = estrdup(f);
    *dsfp = dsf;
    dsfp = &dsf->dsf_next;
  }
  *dsfp = NULL;
  if (!ds->ds_dsf)
    error(0, "missing filenames for %s", spec);

  return ds;
}

struct zone *newzone(struct zone **zonelist,
                     unsigned char *dn, unsigned dnlen,
                     struct mempool *mp) {
  struct zone *zone, **zonep, **lastzonep;
 
  zonep = zonelist;
  lastzonep = NULL;

  for (;;) {
    if (!(zone = *zonep)) {
      if (mp)
        zone = mp_talloc(mp, struct zone);
      else
        zone = tmalloc(struct zone);
      if (!zone)
        return NULL;
      memset(zone, 0, sizeof(*zone));
      if (lastzonep) { zone->z_next = *lastzonep; *lastzonep = zone; }
      else *zonep = zone;
      memcpy(zone->z_dn, dn, dnlen);
      zone->z_dnlen = dnlen;
      zone->z_dnlab = dns_dnlabels(dn);
      zone->z_dslp = &zone->z_dsl;
      break;
    }
    else if (zone->z_dnlen == dnlen && memcmp(zone->z_dn, dn, dnlen) == 0)
      break;
    else {
      if (!lastzonep && zone->z_dnlen < dnlen &&
          memcmp(dn + dnlen - zone->z_dnlen, zone->z_dn, zone->z_dnlen) == 0)
        lastzonep = zonep;
      zonep = &zone->z_next;
    }
  }

  return zone;
}

void connectdataset(struct zone *zone,
                    struct dataset *ds,
                    struct dslist *dsl) {
  dsl->dsl_next = NULL;
  *zone->z_dslp = dsl;
  zone->z_dslp = &dsl->dsl_next;
  dsl->dsl_ds = ds;
  dsl->dsl_queryfn = ds->ds_type->dst_queryfn;
  zone->z_dstflags |= ds->ds_type->dst_flags;
}

struct zone *addzone(struct zone *zonelist, const char *spec) {
  struct zone *zone;
  char *p;
  char name[DNS_MAXDOMAIN];
  unsigned char dn[DNS_MAXDN];
  unsigned dnlen;
  struct dataset *ds;

  p = strchr(spec, ':');
  if (!p || p - spec >= DNS_MAXDOMAIN)
    error(0, "invalid zone spec `%.60s'", spec);

  memcpy(name, spec, p - spec);
  name[p - spec] = '\0';

  dnlen = dns_ptodn(name, dn, sizeof(dn));
  if (!dnlen)
    error(0, "invalid domain name `%.80s'", name);
  dns_dntol(dn, dn);

  p = estrdup(p+1);
  ds = newdataset(p);

  if (!dn[0]) {
    if (!isdstype(ds->ds_type, acl))
      error(0, "missing domain name in `%.60s'", spec);
    if (g_dsacl)
      error(0, "global acl specified more than once");
    g_dsacl = ds;
  }
  else {
    zone = newzone(&zonelist, dn, dnlen, NULL);
    if (isdstype(ds->ds_type, acl)) {
      if (zone->z_dsacl)
        error(0, "repeated ACL definition for zone `%.60s'", name);
      zone->z_dsacl = ds;
    }
    else
      connectdataset(zone, ds, tmalloc(struct dslist));
  }
  free(p);

  return zonelist;
}

/* parse $SPECIAL construct */
static int ds_special(struct dataset *ds, char *line, struct dsctx *dsc) {
  char *w;

  if ((w = firstword_lc(line, "soa"))) {
    /* SOA record */
    struct dssoa dssoa;
    unsigned char odn[DNS_MAXDN], pdn[DNS_MAXDN];
    unsigned odnlen, pdnlen;

    if (isdstype(ds->ds_type, acl))
      return 0;	/* don't allow SOA for ACLs */
    if (ds->ds_dssoa)
      return 1; /* ignore if already set */

    if (!(w = parse_ttl(w, &dssoa.dssoa_ttl, ds->ds_ttl))) return 0;
    if (!(w = parse_dn(w, odn, &odnlen))) return 0;
    if (!(w = parse_dn(w, pdn, &pdnlen))) return 0;
    if (!(w = parse_uint32(w, &dssoa.dssoa_serial))) return 0;
    if (!(w = parse_time_nb(w, dssoa.dssoa_n+0))) return 0;
    if (!(w = parse_time_nb(w, dssoa.dssoa_n+4))) return 0;
    if (!(w = parse_time_nb(w, dssoa.dssoa_n+8))) return 0;
    if (!(w = parse_time_nb(w, dssoa.dssoa_n+12))) return 0;
    if (*w) return 0;

    dssoa.dssoa_odn = mp_memdup(ds->ds_mp, odn, odnlen);
    dssoa.dssoa_pdn = mp_memdup(ds->ds_mp, pdn, pdnlen);
    if (!dssoa.dssoa_odn || !dssoa.dssoa_pdn) return -1;
    ds->ds_dssoa = mp_talloc(ds->ds_mp, struct dssoa);
    if (!ds->ds_dssoa) return -1;
    *ds->ds_dssoa = dssoa;
    return 1;
  }

  if ((w = firstword_lc(line, "ns")) ||
      (w = firstword_lc(line, "nameserver"))) {
     /* NS records */
     unsigned char dn[DNS_MAXDN];
     unsigned dnlen;
     struct dsns *dsns, **dsnslp;
     unsigned ttl;

    if (isdstype(ds->ds_type, acl))
      return 0;	/* don't allow NSes for ACLs */

     if (ds->ds_dsns) return 1; /* ignore 2nd nameserver line */
     dsnslp = &ds->ds_dsns;

     /*XXX parse options (AndrewSN suggested `-bloat') here */

     if (!(w = parse_ttl(w, &ttl, ds->ds_ttl))) return 0;

     do {
       if (*w == '-') {
         /* skip nameservers that start with `-' aka 'commented-out' */
         do ++w; while (*w && !ISSPACE(*w));
         SKIPSPACE(w);
         continue;
       }
       if (!(w = parse_dn(w, dn, &dnlen))) return 0;
       dsns = (struct dsns*)
         mp_alloc(ds->ds_mp, sizeof(struct dsns) + dnlen - 1, 1);
       if (!dsns) return -1;
       memcpy(dsns->dsns_dn, dn, dnlen);
       *dsnslp = dsns;
       dsnslp = &dsns->dsns_next;
       *dsnslp = NULL;
     } while(*w);

     ds->ds_nsttl = ttl;
    return 1;
  }

  if ((w = firstword_lc(line, "ttl"))) {
    unsigned ttl;
    if (!(w = parse_ttl(w, &ttl, def_ttl))) return 0;
    if (*w) return 0;
    if (dsc->dsc_subset) dsc->dsc_subset->ds_ttl = ttl;
    else ds->ds_ttl = ttl;
    return 1;
  }

  if ((w = firstword_lc(line, "maxrange4"))) {
    unsigned r;
    int cidr;
    if (*w == '/') cidr = 1, ++w;
    else cidr = 0;
    if (!(w = parse_uint32(w, &r)) || *w || !r)
      return 0;
    if (cidr) {
      if (r > 32) return 0;
      r = ~ip4mask(r) + 1;
    }
    if (dsc->dsc_ip4maxrange && dsc->dsc_ip4maxrange < r)
      dswarn(dsc, "ignoring attempt to increase $MAXRANGE4 from %u to %u",
             dsc->dsc_ip4maxrange, r);
    else
      dsc->dsc_ip4maxrange = r;
    return 1;
  }

  if (((*(w = line) >= '0' && *w <= '9') || *w == '=') && ISSPACE(w[1])) {
    /* substitution vars */
    unsigned n = w[0] == '=' ? SUBST_BASE_TEMPLATE : w[0] - '0';
    if (dsc->dsc_subset) ds = dsc->dsc_subset;
    if (ds->ds_subst[n]) return 1; /* ignore second assignment */
    w += 2;
    SKIPSPACE(w);
    if (!*w) return 0;
    if (!(ds->ds_subst[n] = mp_strdup(ds->ds_mp, w))) return 0;
    return 1;
  }

  if ((w = firstword_lc(line, "dataset"))) {
    if (!isdstype(ds->ds_type, combined))
      return 0;	/* $dataset is only allowed for combined dataset */
    return ds_combined_newset(ds, w, dsc);
  }

  if ((w = firstword_lc(line, "timestamp"))) {
    time_t stamp, expires;

    if (!(w = parse_timestamp(w, &stamp))) return 0;
    if (!*w)
      expires = 0;
    else if (*w == '+') {       /* relative */
      unsigned n;
      if (!(w = parse_time(w + 1, &n)) || *w) return 0;
      if (!stamp || !n) return 0;
      expires = stamp + n;
      if (expires < 0 || expires - (time_t)n != stamp) return 0;
    }
    else {
      if (!(w = parse_timestamp(w, &expires)) || *w) return 0;
    }
    if (stamp) {
      time_t now = time(NULL);
      if (stamp > now) {
        dslog(LOG_ERR, dsc,
              "data timestamp is %u sec in the future, aborting loading",
              (unsigned)(stamp - now));
        return -1;
      }
    }
    if (expires &&
        (!ds->ds_expires || ds->ds_expires > expires))
      ds->ds_expires = expires;
    return 1;
  }

  return 0;
}

static int
readdslines(struct istream *sp, struct dataset *ds, struct dsctx *dsc) {
  char *line, *eol;
  int r;
  int noeol = 0;
  struct dataset *dscur = ds;
  ds_linefn_t *linefn = dscur->ds_type->dst_linefn;

  while((r = istream_getline(sp, &line, '\n')) > 0) {
    eol = line + r - 1;
    if (noeol) {
      if (*eol == '\n')
        noeol = 0;
      continue;
    }
    ++dsc->dsc_lineno;
    if (*eol == '\n')
      --eol;
    else {
      dswarn(dsc, "long line (truncated)");
      noeol = 1; /* mark it to be read above */
    }
    SKIPSPACE(line);
    while(eol >= line && ISSPACE(*eol))
      --eol;
    eol[1] = '\0';
    if (line[0] == '$' ||
        ((ISCOMMENT(line[0]) || line[0] == ':') && line[1] == '$')) {
      int r = ds_special(ds, line[0] == '$' ? line + 1 : line + 2, dsc);
      if (!r)
        dswarn(dsc, "invalid or unrecognized special entry");
      else if (r < 0)
        return 0;
      dscur = dsc->dsc_subset ? dsc->dsc_subset : ds;
      linefn = dscur->ds_type->dst_linefn;
      continue;
    }
    if (line[0] && !ISCOMMENT(line[0]))
      if (!linefn(dscur, line, dsc))
        return 0;
  }
  if (r < 0)
    return -1;
  if (noeol)
    dslog(LOG_WARNING, dsc, "incomplete last line (ignored)");
  return 1;
}

static void freedataset(struct dataset *ds) {
  ds->ds_type->dst_resetfn(ds->ds_dsd, 0);
  mp_free(ds->ds_mp);
  ds->ds_dssoa = NULL;
  ds->ds_ttl = def_ttl;
  ds->ds_dsns = NULL;
  ds->ds_nsttl = 0;
  ds->ds_expires = 0;
  memset(ds->ds_subst, 0, sizeof(ds->ds_subst));
}

int loaddataset(struct dataset *ds) {
  struct dsfile *dsf;
  time_t stamp = 0;
  struct istream is;
  int fd;
  int r;
  struct stat st0, st1;
  struct dsctx dsc;

  freedataset(ds);

  memset(&dsc, 0, sizeof(dsc));
  dsc.dsc_ds = ds;

#ifndef NO_DSO
  if (  extloaddataset
     && ds
     && ds->ds_type
     && ds->ds_type->dst_name
     && strcmp(ds->ds_type->dst_name, "extension") == 0) {
    return extloaddataset(ds);
  }
#endif

  for(dsf = ds->ds_dsf; dsf; dsf = dsf->dsf_next) {
    dsc.dsc_fname = dsf->dsf_name;
    fd = open(dsf->dsf_name, O_RDONLY);
    if (fd < 0 || fstat(fd, &st0) < 0) {
      dslog(LOG_ERR, &dsc, "unable to open file: %s", strerror(errno));
      if (fd >= 0) close(fd);
      goto fail;
    }
    ds->ds_type->dst_startfn(ds);
    istream_init_fd(&is, fd);
    if (istream_compressed(&is)) {
      if (nouncompress) {
        dslog(LOG_ERR, &dsc, "file is compressed, decompression disabled");
        r = 0;
      }
      else {
#ifdef NO_ZLIB
        dslog(LOG_ERR, &dsc,
              "file is compressed, decompression is not compiled in");
        r = 0;
#else
        r = istream_uncompress_setup(&is);
          /* either 1 or -1 but not 0 */
#endif
      }
    }
    else
      r = 1;
    if (r > 0) r = readdslines(&is, ds, &dsc);
    if (r > 0) r = fstat(fd, &st1) < 0 ? -1 : 1;
    dsc.dsc_lineno = 0;
    istream_destroy(&is);
    close(fd);
    if (!r)
      goto fail;
    if (r < 0) {
      dslog(LOG_ERR, &dsc, "error reading file: %s", strerror(errno));
      goto fail;
    }
    if (st0.st_mtime != st1.st_mtime ||
        st0.st_size  != st1.st_size) {
      dslog(LOG_ERR, &dsc,
            "file changed while we where reading it, data load aborted");
      dslog(LOG_ERR, &dsc,
            "do not write data files directly, "
            "use temp file and rename(2) instead");
      goto fail;
    }
    dsf->dsf_stamp = st0.st_mtime;
    dsf->dsf_size  = st0.st_size;
    if (dsf->dsf_stamp > stamp)
      stamp = dsf->dsf_stamp;
  }
  ds->ds_stamp = stamp;
  dsc.dsc_fname = NULL;

  ds->ds_type->dst_finishfn(ds, &dsc);

  return 1;

fail:
  freedataset(ds);
  for (dsf = ds->ds_dsf; dsf; dsf = dsf->dsf_next)
    dsf->dsf_stamp = 0;
  ds->ds_stamp = 0;
  return 0;
}

/* find next dataset which needs reloading */
struct dataset *nextdataset2reload(struct dataset *ds) {
  struct dsfile *dsf;
  for (ds = ds ? ds->ds_next : ds_list; ds; ds = ds->ds_next)
    for(dsf = ds->ds_dsf; dsf; dsf = dsf->dsf_next) {
      struct stat st;
      if (stat(dsf->dsf_name, &st) < 0)
        return ds;
      if (dsf->dsf_stamp != st.st_mtime ||
          dsf->dsf_size  != st.st_size)
        return ds;
    }
  return NULL;
}

#ifndef NO_MASTER_DUMP
void dumpzone(const struct zone *z, FILE *f) {
  const struct dslist *dsl;
  { /* zone header */
    char name[DNS_MAXDOMAIN+1];
    const unsigned char *const *nsdna = z->z_nsdna;
    const struct dssoa *dssoa = z->z_dssoa;
    unsigned nns = z->z_nns;
    unsigned n;
    dns_dntop(z->z_dn, name, sizeof(name));
    fprintf(f, "$ORIGIN\t%s.\n", name);
    if (z->z_dssoa) {
      fprintf(f, "@\t%u\tSOA", dssoa->dssoa_ttl);
      dns_dntop(dssoa->dssoa_odn, name, sizeof(name));
      fprintf(f, "\t%s.", name);
      dns_dntop(dssoa->dssoa_pdn, name, sizeof(name));
      fprintf(f, "\t%s.", name);
      fprintf(f, "\t(%u %u %u %u %u)\n",
          dssoa->dssoa_serial ? dssoa->dssoa_serial : z->z_stamp,
          unpack32(dssoa->dssoa_n+0),
          unpack32(dssoa->dssoa_n+4),
          unpack32(dssoa->dssoa_n+8),
          unpack32(dssoa->dssoa_n+12));
    }
    for(n = 0; n < nns; ++n) {
      dns_dntop(nsdna[n], name, sizeof(name));
      fprintf(f, "\t%u\tNS\t%s.\n", z->z_nsttl, name);
    }
  }
  for (dsl = z->z_dsl; dsl; dsl = dsl->dsl_next) {
    fprintf(f, "$TTL %u\n", dsl->dsl_ds->ds_ttl);
    dsl->dsl_ds->ds_type->dst_dumpfn(dsl->dsl_ds, z->z_dn, f);
  }
}
#endif
