/* Implementation of the TOTP (Time-based One-Time Password) algorithm
   as defined by RFC 6238 (which is turn uses RFC 4226 and RFC 2104),
   with base32-encoded keys (RFC 3548) as used by most 2-Factor
   Authentication (2FA) programs/apps.

   This implementation was done from scratch based on the standards and
   is intended to be minimalistic in a single C file. Its only
   dependency is one HMAC-SHA1 function calculation which is done
   using OpenSSL crypto library, but can be provided by any other
   library.

   (C)Copyright 2023 Simon Urbanek <urbanek@R-project.org>
   License: MIT

*/   

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

/* this is the only dependency (one-line implmentation with OpenSSL below) */
/* In our case the payload length is fixed: 8 bytes */
unsigned char *hmac_sha1(unsigned char *key, size_t key_len, const unsigned char *tt, unsigned char h[20]);

#ifndef HAVE_HMAC_SHA1
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* compute HMAC-SHA1 - here using OpenSSL, but any library will do */
unsigned char *hmac_sha1(unsigned char *key, size_t key_len, const unsigned char *tt, unsigned char h[20]) {
    unsigned int hlen = 20;
    return HMAC(EVP_sha1(), key, key_len, tt, 8, h, &hlen);
}
#endif

/* --- cut here - actual implementation --- */

/* base32 decoding so we can read in keys */
const char b32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int verb = 0;

static size_t base32decode(unsigned char *dst, size_t max_len, const char *src) {
    size_t len = 0;
    uint64_t acc = 0;
    int sh = 0, pad = 0;
    while ((src && *src && len < max_len) || sh) {
	while (src && *src && len < max_len && sh < 8) {
	    const char *w = strchr(b32, *(src++));
	    if (!w) {
		src = 0;
		break;
	    }
	    acc <<= 5;
	    acc |= (unsigned int) (w - b32);
	    sh++;
	}
	/* pad fully at EOL */
	while ((!src || !*src) && sh < 8) {
	    if (!sh) break; /* nothing left */
	    acc <<= 5;
	    sh++;
	    /* remember padding so we know how much to ignore */
	    pad += 5;
	}
	if (sh == 8) {
	    sh = 5;
	    pad = (pad + 7) / 8;
	    sh -= pad; /* remove padding */
	    while (sh && len < max_len) {
		dst[len++] = (unsigned char) ((acc >> 32) & 255);
		acc <<= 8;
		sh--;
	    }
	    sh = 0;
	    acc = 0;
	}
    }
    return len;
}

/* --- compute TOTP of "dig" digits, based on time "t" and provided key ---*/

static char *totp(char *res, int dig, uint64_t t, unsigned char *key, size_t key_len) {
    unsigned char tt[8];
    int i = 8;
    while (i--) {
	tt[i] = (unsigned char) (t & 255);
	t >>= 8;
    }
    if (verb) {
	printf("T: ");
	for(int i = 0; i < 8; i++) printf("%02x", (int)tt[i]);
	printf("\n");
    }
    /* hmac/sha1 (t, key) -> 20 bytes */
    unsigned char h[20];
    if (!hmac_sha1(key, key_len, tt, h)) {
	fprintf(stderr, "HMAC calculation error\n");
	return 0;
    }
    if (verb) {
	printf("HMAC: ");
	for(int i = 0; i < 20; i++) printf("%02x", (int)h[i]);
	printf("\n");
    }
    /* offset = hash[19] & 15
       take int32_t (big-end) at hash + offset
       (ignore MSB so always positive)
       modulo in base10 for result */
    size_t off = (size_t) (h[19] & 15);
    uint32_t num = (((uint32_t) (h[off] & 127)) << 24) |
	(((uint32_t) (h[off + 1])) << 16) |
	(((uint32_t) (h[off + 2])) << 8) |
	((uint32_t) h[off + 3]);
    res[dig] = 0;
    while (dig--) {
	res[dig] = (num % 10) + '0';
	num /= 10;
    }
    return res;
}


/* --- main front-end --- */
int main(int ac, char **av) {
    const char *fn  = 0;
    const char *tv  = 0;
    const char *k32 = 0;
    int i = 0, just1 = 0, dig = 6;
    long step = 30;
    while (++i < ac)
	if (av[i][0] == '-')
	    switch(av[i][1]) {
	    case 0: fn = "-"; break;
	    case 't': if (av[i][2]) tv = av[i] + 2; else if (++i < ac) tv = av[i]; break;
	    case 'k': if (++i < ac) k32 = av[i]; break;
	    case 'd': if (av[i][2]) dig = atoi(av[i] + 2); else if (++i < ac) dig = atoi(av[i]); break;
	    case 's': if (av[i][2]) step = atol(av[i] + 2); else if (++i < ac) step = atol(av[i]); break;
	    case 'v': { char *c = av[i] + 1; while (*(c++) == 'v') verb++; break; }
	    case '1': just1 = 1; break;
	    case 'h':
		printf("\n"
" Usage: %s [-v] [-1] [-t <time>] [-s <step>] [-d <digits>] <key-file>\n"
"        %s [-v] [-1] [-t <time>] [-s <step>] [-d <digits>] -k <key>\n"
"        %s -h\n\n"
" By default current and next token are printed with\n"
" expiry information. Use -1 to just print the current token.\n"
" <key-file> can be - for key input on stdin.\n"
"\n", av[0], av[0], av[0]);
		return 0;
	    } else if (!fn && !k32)
	    fn = av[i];
	else if (!tv)
	    tv = av[i];

    if (!fn && !k32) {
	fprintf(stderr, "ERROR: missing key\n");
	return 1;
    }
    if (fn && k32) {
	fprintf(stderr, "ERROR: too many key specifications, pick one\n");
	return 1;
    }
    if (dig < 1 || dig > 10) {
	fprintf(stderr, "ERROR: <digits> must be 1..10\n");
	return 1;
    }
    unsigned char key[64];
    char buf[64];
    if (fn) {
	FILE *f = (fn[0] == '-' && !fn[1]) ? stdin: fopen(fn, "r");
	if (!f) {
	    fprintf(stderr, "Error: cannot open %s\n", fn);
	    return 1;
	}
	if (!fgets(buf, sizeof(buf) - 1, f) || !*buf) {
	    fprintf(stderr, "Error: no key found\n");
	    return 1;
	}
	k32 = buf;
    }
    /* decode key */
    size_t n = base32decode(key, sizeof(key), k32);
    if (verb > 1) {
	printf("Key: ");
	for(int i = 0; i < n; i++) printf("%02x", (int)key[i]);
	printf("\n");
    }
    /* time() / 30 --> uint64_t, big-endian */
    uint64_t t = (uint64_t) (tv ? atol(tv) : time(0));
    if (!just1 && step > 1)
	printf("(valid for %ld sec)\n", (long) (((t / step) + 1) * step - t));
    t /= (uint64_t) step;
    char res[16];
    if (!totp(res, dig, t, key, n))
	return 1;
    puts(res);
    if (!just1) {
	t++;
	if (!totp(res, dig, t, key, n))
	    return 1;
	puts(res);
    }
    return 0;
}
