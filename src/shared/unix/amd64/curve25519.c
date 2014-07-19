/*===-- curve25519.c ------------------------*- shared/unix/amd64 -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/misc/curve25519.h"
#include "ordo/misc/os_random.h"

/*===----------------------------------------------------------------------===*/

typedef uint8_t u8;
typedef uint64_t felem;

static void fsum(felem *output, const felem *in)
HOT_CODE;
extern void fmul(felem *output, const felem *in1, const felem *in2);
extern void fsquare(felem *output, const felem *in1);
extern void fexpand(felem *ouptut, const u8 *input);
extern void fcontract(u8 *output, const felem *input);
extern void freduce_coefficients(felem *inout);
extern void fscalar(felem *output, const felem *input);
extern void fdifference_backwards(felem *output, const felem *input);
extern void cmult(felem *x, felem *z, const u8 *n, const felem *q);
static void crecip(felem *out, const felem *z)
HOT_CODE;
void fmonty(felem *x2,
            felem *x3,
            felem *x,
            felem *xprime,
            const felem *qmqp)
HOT_CODE;
static void curve25519_donna(u8 *mypublic, const u8 *secret,
                             const u8 *basepoint)
HOT_CODE;

/*===----------------------------------------------------------------------===*/

int curve25519_gen(void *priv)
{
    int err = os_secure_random(priv, bits(256));
    if (!err) return err;
    *((uint8_t *)priv +  0) &= 248;
    *((uint8_t *)priv + 31) &= 127;
    *((uint8_t *)priv + 31) |=  64;
    return ORDO_SUCCESS;
}

void curve25519_pub(void *pub, const void *priv)
{
    static const uint8_t basepoint[32] = { 9 };
    curve25519_donna(pub, priv, basepoint);
}

void curve25519_ecdh(void *shared, const void *priv, const void *other)
{
    curve25519_donna(shared, priv, other);
}

/*===----------------------------------------------------------------------===*/

/* Original license for this curve25519 implementation as follows: */

/* 2008, Google Inc.
 * Code released into the public domain
 *
 * curve25519: Curve25519 elliptic curve, public key function
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation.
 *
 * You have to have read the curve25519 paper to understand this code:
 *   http://cr.yp.to/ecdh/curve25519-20060209.pdf
 *
 * DJB used limb sizes of ceil(25.5) bits in a 64-bit limb. Thus he has 10
 * limbs in a reduced coefficient form. Here, we use 51-bits in a 64-bit limb.
 * This means that we use the full 64x64->128 bit mult in x86-64 and are often
 * dealing with 128-bit values.
 *
 * Thus values are stored in arrays of 5 uint64_t's. Index 0 is the least
 * significant value. We maintain that the limbs are always positive. The only
 * place where this can change is in fdifference_backwards, so we fix up any
 * negative values by carrying between them.
 */

/* Sum two numbers: output += in */
void fsum(felem *output, const felem *in) {
  output[0] = output[0] + in[0];
  output[1] = output[1] + in[1];
  output[2] = output[2] + in[2];
  output[3] = output[3] + in[3];
  output[4] = output[4] + in[4];
}

/* Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   x2 z3: long form
 *   x3 z3: long form
 *   x z: short form, destroyed
 *   xprime zprime: short form, destroyed
 *   qmqp: short form, preserved
 */
void fmonty(felem *x2,  /* output 2Q */
            felem *x3,  /* output Q + Q' */
            felem *x,    /* input Q */
            felem *xprime,  /* input Q' */
            const felem *qmqp /* input Q - Q' */) {
  felem *const z2 = &x2[8];
  felem *const z3 = &x3[8];
  felem *const z = &x[8];
  felem *const zprime = &xprime[8];
  felem origx[5], origxprime[5], zzz[5], xx[5], zz[5], xxprime[5],
        zzprime[5], zzzprime[5];

  memcpy(origx, x, 5 * sizeof(felem));
  fsum(x, z);
  fdifference_backwards(z, origx);  /* does x - z */

  memcpy(origxprime, xprime, sizeof(felem) * 5);
  fsum(xprime, zprime);
  fdifference_backwards(zprime, origxprime);
  fmul(xxprime, xprime, z);
  fmul(zzprime, x, zprime);
  memcpy(origxprime, xxprime, sizeof(felem) * 5);
  fsum(xxprime, zzprime);
  fdifference_backwards(zzprime, origxprime);
  fsquare(x3, xxprime);
  fsquare(zzzprime, zzprime);
  fmul(z3, zzzprime, qmqp);

  fsquare(xx, x);
  fsquare(zz, z);
  fmul(x2, xx, zz);
  fdifference_backwards(zz, xx);  /* does zz = xx - zz */
  fscalar(zzz, zz); /* * 121665 */
  freduce_coefficients(zzz);
  fsum(zzz, xx);
  fmul(z2, zz, zzz);
}

/* -----------------------------------------------------------------------------
** Shamelessly copied from djb's code
** ---------------------------------------------------------------------------*/
void crecip(felem *out, const felem *z) {
  felem z2[5];
  felem z9[5];
  felem z11[5];
  felem z2_5_0[5];
  felem z2_10_0[5];
  felem z2_20_0[5];
  felem z2_50_0[5];
  felem z2_100_0[5];
  felem t0[5];
  felem t1[5];
  int i;

  /* 2 */ fsquare(z2,z);
  /* 4 */ fsquare(t1,z2);
  /* 8 */ fsquare(t0,t1);
  /* 9 */ fmul(z9,t0,z);
  /* 11 */ fmul(z11,z9,z2);
  /* 22 */ fsquare(t0,z11);
  /* 2^5 - 2^0 = 31 */ fmul(z2_5_0,t0,z9);

  /* 2^6 - 2^1 */ fsquare(t0,z2_5_0);
  /* 2^7 - 2^2 */ fsquare(t1,t0);
  /* 2^8 - 2^3 */ fsquare(t0,t1);
  /* 2^9 - 2^4 */ fsquare(t1,t0);
  /* 2^10 - 2^5 */ fsquare(t0,t1);
  /* 2^10 - 2^0 */ fmul(z2_10_0,t0,z2_5_0);

  /* 2^11 - 2^1 */ fsquare(t0,z2_10_0);
  /* 2^12 - 2^2 */ fsquare(t1,t0);
  /* 2^20 - 2^10 */ for (i = 2;i < 10;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
  /* 2^20 - 2^0 */ fmul(z2_20_0,t1,z2_10_0);

  /* 2^21 - 2^1 */ fsquare(t0,z2_20_0);
  /* 2^22 - 2^2 */ fsquare(t1,t0);
  /* 2^40 - 2^20 */ for (i = 2;i < 20;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
  /* 2^40 - 2^0 */ fmul(t0,t1,z2_20_0);

  /* 2^41 - 2^1 */ fsquare(t1,t0);
  /* 2^42 - 2^2 */ fsquare(t0,t1);
  /* 2^50 - 2^10 */ for (i = 2;i < 10;i += 2) { fsquare(t1,t0); fsquare(t0,t1); }
  /* 2^50 - 2^0 */ fmul(z2_50_0,t0,z2_10_0);

  /* 2^51 - 2^1 */ fsquare(t0,z2_50_0);
  /* 2^52 - 2^2 */ fsquare(t1,t0);
  /* 2^100 - 2^50 */ for (i = 2;i < 50;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
  /* 2^100 - 2^0 */ fmul(z2_100_0,t1,z2_50_0);

  /* 2^101 - 2^1 */ fsquare(t1,z2_100_0);
  /* 2^102 - 2^2 */ fsquare(t0,t1);
  /* 2^200 - 2^100 */ for (i = 2;i < 100;i += 2) { fsquare(t1,t0); fsquare(t0,t1); }
  /* 2^200 - 2^0 */ fmul(t1,t0,z2_100_0);

  /* 2^201 - 2^1 */ fsquare(t0,t1);
  /* 2^202 - 2^2 */ fsquare(t1,t0);
  /* 2^250 - 2^50 */ for (i = 2;i < 50;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
  /* 2^250 - 2^0 */ fmul(t0,t1,z2_50_0);

  /* 2^251 - 2^1 */ fsquare(t1,t0);
  /* 2^252 - 2^2 */ fsquare(t0,t1);
  /* 2^253 - 2^3 */ fsquare(t1,t0);
  /* 2^254 - 2^4 */ fsquare(t0,t1);
  /* 2^255 - 2^5 */ fsquare(t1,t0);
  /* 2^255 - 21 */ fmul(out,t1,z11);
}

void curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint) {
  felem bp[5], x[5], z[5], zmone[5];
  /* The assembly code calls back into fmonty, but the compiler understandably
   * might not realize that - give it a hint so fmonty is not marked unused.
   */
  (void)fmonty;
  fexpand(bp, basepoint);
  cmult(x, z, secret, bp);
  crecip(zmone, z);
  fmul(z, x, zmone);
  fcontract(mypublic, z);
}
