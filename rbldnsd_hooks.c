/* $Id$
 * hook implementation for rbldnsd.  To be user-defined.
 */

#include "rbldnsd.h"
#include "rbldnsd_hooks.h"

#ifdef TRUSTED_QUERY_LOGGING

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>

/* example of implementation:
 * we're logging positive queries made by a list of trusted clients.
 * Trusted clients (IP addresses) are defined in -H cli:filename,
 * and query logging goes to -H log:filename.
 */
const char *hook_info = " (tql 0.1)";

static char *clifn;
static time_t clifn_timestamp;
static char *logfn;

static ip4addr_t *cliip;
static unsigned ncliip;
static unsigned acliip;

#define STEP 64

int hook_getopt(char *optarg) {
  if (memcmp(optarg, "log:", 4) == 0) logfn = optarg + 4;
  else if (memcmp(optarg, "cli:", 4) == 0) clifn = optarg + 4;
  else return -1;
  return 0;
}

void hook_query_result(const struct sockaddr *cli, const struct zone *zone,
                       const struct dnsqinfo *qi, int positive) {
  ip4addr_t q;
  int a, b, m;
  char s[64];
  if (positive) return;
  if (!qi->qi_ip4valid) return;
  if (cli->sa_family != AF_INET) return;
  q = ntohl(((struct sockaddr_in*)cli)->sin_addr.s_addr);
  a = 0; b = ncliip - 1;
  for(;;) {
    if (a > b) return; /* not found */
    m = (a + b) >> 1;
    if (cliip[m] > q) b = m - 1;
    else if (cliip[m] < q) a = m + 1;
    else break;
  }
  /* note: in case of excessive amount of queries,
   * the file may grow pretty quickly.
   */
  a = open(logfn, O_WRONLY|O_APPEND|O_CREAT, 0644);
  if (a < 0) return;
  m = sprintf(s, "%s\n", ip4atos(qi->qi_ip4));
  write(a, s, m);
  close(a);
}

static int read_cli_list(FILE *f) {
  char buf[512];
  ip4addr_t a;
  char *p, *e;
  int lineno = 0;
  int warns = 0;
  int ret = 0;
  unsigned ne = 0;
  unsigned ae = acliip;

  while(fgets(buf, sizeof(buf), f)) {
    ++lineno;
    p = buf;
    while(*p == ' ' || *p == '\t') ++p;
    if (*p == '#' || *p == '\n') continue;
    if (ip4addr(p, &a, &e) < 0) {
      if (warns++ < 5)
        dslog(LOG_WARNING, 0, "%.50s:%d: invalid IP address", clifn, lineno);
      continue;
    }
    if (ne >= ae) {
      ip4addr_t *newcli =
        (ip4addr_t*)erealloc(cliip, (ae + STEP) * sizeof(ip4addr_t));
      if (!newcli) {
        dslog(LOG_WARNING, 0,
              "unable to read list of client IPs: out of memory");
	ret = -1;
	break;
      }
      cliip = newcli;
      ae += STEP;
    }
    cliip[ne++] = a;
  }
  if (ne) {
    ae = (ne + STEP - 1) / STEP * STEP;
#   define QSORT_TYPE ip4addr_t
#   define QSORT_BASE cliip
#   define QSORT_NELT ne
#   define QSORT_LT(a,b) *a < *b
#   include "qsort.c"
#   define eeq(a,b) a == b
    REMOVE_DUPS(ip4addr_t, cliip, ne, eeq);
    SHRINK_ARRAY(ip4addr_t, cliip, ne, ae);
  }
  ncliip = ne;
  acliip = ae;
  return ret;
}

int hook_reload(const struct zone *zonelist) {
  struct stat st;
  FILE *f;
  int ret;
  if (stat(clifn, &st) < 0) return -1;
  if (st.st_mtime == clifn_timestamp) return 0;
  start_loading();
  f = fopen(clifn, "r");
  if (f == NULL) return -1;
  ret = read_cli_list(f);
  fclose(f);
  return ret;
}

#else /* ! TRUSTED_QUERY_LOGGING */

/* dummy routines */
const char *hook_info = "";

#if 0
int hook_getopt(char *optarg) { return 0; }
int hook_init(const struct zone *zonelist) { return 0; }
int hook_reload(const struct zone *zonelist) { return 0; }
int hook_query_access(const struct sockaddr *requestor,
                      const struct zone *zone,
                      const struct dnsqinfo *qinfo) {
  return 0;
}
void hook_query_result(const struct sockaddr *requestor,
                       const struct zone *zone,
                       const struct dnsqinfo *qinfo,
                       int positive) {
}
#endif

#endif
