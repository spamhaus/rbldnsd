/* $Id$
 * common #include header for various helper routines to
 * manipulate IP4 addreses
 */

#ifndef _IP4ADDR_H_INCLUDED
#define _IP4ADDR_H_INCLUDED

#ifndef NOSTDINT_H /* some BSDs have no C98 stdint.h header */
# include <stdint.h>
#else
# include <sys/types.h>
#endif

typedef uint32_t ip4addr_t; /* host byte order */


/* parse string to ip4addr_t (if np specified, return
 * pointer to the next characted in it)...: */

/*  ..single address, like inet_aton/inet_addr,
 *    return #bits in _prefix_ (32,24,16 or 8) or 0 on error */
unsigned ip4addr(const char *s, ip4addr_t *ap, char **np);

/*  ..prefix, 1.2.3.4 or 1.2.3 or 1.2, return number of bits or 0 */
unsigned ip4prefix(const char *s, ip4addr_t *ap, char **np);

/*  ..CIDR range, return number of bits or 0 if error */
unsigned ip4cidr(const char *s, ip4addr_t *ap, char **np);

/*  ..range of addresses (inclusive) or CIDR, return #bits if
 *    that was CIDR or prefix or 32 if plain range, 0 on error */
unsigned ip4range(const char *s, ip4addr_t *ap, ip4addr_t *bp, char **np);


/* inet_ntoa() */
const char *ip4atos(ip4addr_t a);

/* convert #bits into mask */
ip4addr_t ip4mask(unsigned bits);

#define IP4A_LOOPBACK 0x7f000000

#endif
