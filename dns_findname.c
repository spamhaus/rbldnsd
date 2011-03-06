/* dns_findname() is an auxilary routine to find given name in a
 * given dns_nameval table.
 */

#include "dns.h"
#include <string.h>

const struct dns_nameval *
dns_findname(const struct dns_nameval *nv, const char *name) {
  char nm[60]; /* all names are less than 60 chars anyway */
  char *p = nm;
  while(*name) {
    if (*name >= 'a' && *name <= 'z')
      *p++ = *name++ - 'a' + 'A';
    else
      *p++ = *name++;
    if (p == nm + sizeof(nm) - 1)
      return NULL;
  }
  *p = '\0';
  while(nv->name)
    if (strcmp(nv->name, nm) == 0)
      return nv;
    else
      ++nv;
  return NULL;
}
