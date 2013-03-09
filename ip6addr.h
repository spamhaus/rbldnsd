/* common #include header for various helper routines to
 * manipulate IP6 addreses.
 */

#ifndef _IP6ADDR_H_INCLUDED
#define _IP6ADDR_H_INCLUDED

/* IPv6 address is just 16 bytes.  Sometimes only part of
 * all 16 bytes can be used, most commonly it's 64 bits (8 bytes).
 * All routines accepts pointer to ip6oct_t array of size IP6ADDR_FULL
 * bytes.
 */
typedef unsigned char ip6oct_t;

#define IP6ADDR_FULL 16
#define IP6ADDR_HALF 8

/* parse string to ip6oct_t (if np specified, return
 * pointer to the next characted in the input buffer)...: */

/*  ..prefix, ffff:ffff:ffff...
 *    Return number of _bits_ (16,32,48,...) or <0 on error/ */
int ip6prefix(const char *s, ip6oct_t ap[IP6ADDR_FULL], char **np);

#define ip6addr(s,ap,np) ip6prefix((s),(ap),(np))

/*  ..CIDR range, return number of bits or <0 if error.
 *    does NOT zerofill hostpart */
int ip6cidr(const char *s, ip6oct_t ap[IP6ADDR_FULL], char **np);

/* applies a /bits mask to v6 address in ap
 * and optionally stores result into bp (if non-NULL).
 * Both ap and bp are of size n bytes.
 * return >1 if any of host bits in a are non-zero
 * or 0 if all host bits are zero.
 */
int ip6mask(const ip6oct_t *ap, ip6oct_t *bp, unsigned n, unsigned bits);

/* inet_ntoa().
 * This routine accepts `an' as size of ap buffer, in bytes.
 */
const char *ip6atos(const ip6oct_t *ap, unsigned an);

#endif
