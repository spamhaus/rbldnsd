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
  a = open(logfn, O_WRONLY|O_APPEND|O_CREAT, 0644);
  if (a < 0) return;
  stpcpy(stpcpy(s, ip4atos(qi->qi_ip4)), "\n");
  write(a, s, strlen(s));
  close(a);
}

static int read_cli_list(FILE *f) {
  char buf[512];
  ip4addr_t a;
  char *p;
  /* read lines from f, parse IP addresses and add them to cliip array;
   * qsort it at the end, #including "qsort.h" */
  return 0;
}

int hook_reload(const struct zone *zonelist) {
  struct stat st;
  FILE *f;
  if (stat(clifn, &st) < 0) return -1;
  if (st.st_mtime == clifn_timestamp) return 0;
  start_loading();
  f = fopen(clifn, "r");
  if (f == NULL) return -1;
  read_cli_list(f);
  fclose(f);
  return 0;
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
