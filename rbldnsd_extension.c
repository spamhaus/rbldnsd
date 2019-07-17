#include <stdio.h>
#include "rbldnsd.h"
#include <syslog.h>

#ifndef NO_DSO

extern int extension_loaded;
extern char *extarg;

struct dsdata {
  /* correlates to any -X arguments given at start of program */
  char *extargs;

  /* correlates to dataset file */
  char *dataset_file;
};

definedstype(extension, DSTF_IP4REV, "extension that handles responses to IPv4 lookups");

/*
 * extension 'reset' handler wrapper.
 *
 * This is called at start of program and intended to flush any memory
 * the dataset is currently using, then load up fresh data.  Also called
 * any time a reload / refresh is enacted by the parent daemon.
 *
 * NOTE: the safety check 'extension_loaded' will implicitly break any 'dump'
 *       calls - this is because extensions are loaded *after* dump flag
 *       processing takes place.
 */
static void ds_extension_reset(struct dsdata *dsd, int freeall)
{
  if (!extension_loaded)
    error(0, "critical error - extension reset called with no extension loaded");

  /* initialize the dataset 'extarg' as required */
  if (!dsd->extargs && extarg)
    dsd->extargs = extarg;

  if (extreset)
    extreset(dsd, freeall);
}

static void ds_extension_start(struct dataset *ds)
{
  if (!extension_loaded)
    error(0, "critical error - extension start called with no extension loaded");

  if (extstart)
    extstart(ds);
}

static int ds_extension_line(struct dataset *ds, char *s, struct dsctx *dsc)
{
  if (!extension_loaded)
    error(0, "critical error - extension line called with no extension loaded");

  if (extline)
    return extline(ds, s, dsc);

  return 1;
}

static void ds_extension_finish(struct dataset *ds, struct dsctx *dsc)
{
  if (!extension_loaded)
    error(0, "critical error - extension finish called with no extension loaded");

  if (extfinish)
    extfinish(ds, dsc);
}

static int ds_extension_query(
              const struct dataset *ds,
              const struct dnsqinfo *qi,
              struct dnspacket *pkt)
{
  if (!extension_loaded)
    error(0, "critical error - extension query called with no extension loaded");

  if (!extquery)
    error(0, "critical error - extension query called with no query function defined");

  return extquery(ds, qi, pkt);
}

#ifndef NO_MASTER_DUMP
static void ds_extension_dump(
                  const struct dataset *ds,
                  const unsigned char *odn,
                  FILE *f)
{
  if (extdump)
    extdump(ds, odn, f);
}

#endif

#endif
