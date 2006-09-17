#include "rbldnsd.h"
#include <stdio.h>

/* reload_check hook is called to test whenever an extension
 * needs to reload its data.  It should not modify any
 * data structures, just return true/false.
 */
static int
reload_check(const struct zone *z) {
  fprintf(stderr, "reload check\n");
  return 0;
}

/* reload hook performs actual reload of any data files.
 * it should only reload if necessary.
 * it can be called if reload_check() hasn't been called at all,
 * or it can be called if reload_check() has been called but
 * returned false.
 * Should return 0 on ok, !0 on failure
 */
static int
reload(struct zone *zonelist) {
  fprintf(stderr, "reload\n");
  return 0;
}

/* query_access hook is called to check if requestor has permissions
 * to query the given zone for the query in qi.
 * Return: 0 for normal processing, <0 if to ignore the query, >0 to refuse
 */
static int
query_access(const struct sockaddr *requestor,
             const struct zone *zone,
	     const struct dnsqinfo *qinfo) {
  fprintf(stderr, "query access\n");
  return 0;
}

/* query_result hook is used for logging and statistics.
 * return value is ignored
 * Note that in fork-on-reload mode, statistics are NOT passed back to
 * parent process.  For now, anyway.
 */
static int
query_result(const struct sockaddr *requestor,
             const struct zone *zone,
             const struct dnsqinfo *qinfo,
             int positive) {
  fprintf(stderr, "query result\n");
  return 0;
}

/* an initialisation routine.
 * Open any logfiles if needed (and reopen in reload() if needed)
 * process (command-line) arg if any
 * return 0 on success.
 * Don't initialize hooks which aren't needed.
 */
int rbldnsd_extension_init(char *arg, struct zone *zonelist) {
  hook_reload_check = reload_check;
  hook_reload = reload;
  hook_query_access = query_access;
  hook_query_result = query_result;
  return 0;
}
