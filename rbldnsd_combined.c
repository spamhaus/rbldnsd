/* $Id$
 * combined dataset, one file is a collection of various datasets
 * and subzones.  Special case.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "rbldnsd.h"

struct dataset {
  int dummy;
};

definedstype(combined, DSTF_ZERODN, "several datasets/subzones combined");

static void ds_combined_reset(struct dataset *ds) {
  memset(ds, 0, sizeof(*ds));
}

static int
ds_combined_parseline(struct zonedataset *zds, char *s, int lineno) {
  dswarn(lineno, "invalid/unrecognized entry");
  return 1;
}

static int ds_combined_load(struct zonedataset *zds, FILE *f) {
  return readdslines(f, zds, ds_combined_parseline);
}

static int ds_combined_finish(struct dataset *ds) {
  return 1;
}

static int
ds_combined_query(const struct zonedataset *zds, const struct dnsquery *qry,
                 struct dnspacket *pkt) {
  return 1;
}

static void ds_combined_dump(const struct zonedataset *zds, FILE *f) {
}
