/* $Id$
 * rbldnsd zone data structures.
 */

/*
 * Each zone is composed of a set of zonedatasets.
 * There is a global list of zonedatas, each
 * with a timestamp etc.
 * Each zonedata is composed of a list of files.
 */

struct zonefile {
  time_t stamp;			/* last timestamp of this file */
  struct zonefile *next;	/* next file in list */
  const char *name;		/* name of this file */
};

struct zonedataset {
  const struct zonetype *type;	/* type of this data */
  z_queryfn *queryfn;		/* cached from type */
  unsigned qfilter;		/* cached from type */
  struct zonedata *data;	/* type-specific data */
  time_t stamp;			/* timestamp: when loaded */
  const char *spec;		/* original specification */
  struct zonefile *file;	/* list of files for this data */
  struct zonedataset *next;	/* next in global list */
};

struct zonedatalist {
  struct zonedataset *set;
  struct zonedatalist *next;
};

struct zone {
  char *name;			/* name of the zone */
  int loaded;			/* true if loaded ok */
  unsigned char *dn;		/* domain name */
  unsigned dnlen;		/* length of dn */
  unsigned dnlab;		/* number of dn labels */
  struct zonedatalist *dlist;	/* list of datas */
  struct zone *next;		/* next in list */
};

