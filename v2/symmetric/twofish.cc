//
// Copyright 2014 John Manferdelli, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// See README for original license from aes authors which is incorporated here
//      by reference.
// File: twofish.cc

#include "crypto_support.h"
#include "symmetric_cipher.h"
#include "twofish.h"

// Fast, portable, and easy-to-use two_fish implementation,
// Version 0.3.
// Copyright (c) 2002 by Niels Ferguson.
// The author hereby grants a perpetual license to everybody to
// use this code for any purpose as long as the copyright message is included
// in the source code of this or any derived work.
// Yes, this means that you,your company, your club, and anyone else
// can use this code anywhere you want. You can change it and distribute it
// under the GPL, include it in your commercial product without releasing
// the source code, put it on the web, etc.

#define UINT32_MASK ((((uint32_t)2) << 31) - 1)
#define ROL32(x, n) ((x) << (n) | ((x)&UINT32_MASK) >> (32 - (n)))
#define ROR32(x, n) ((x) >> (n) | ((x)&UINT32_MASK) << (32 - (n)))
#define CONVERT_USING_CASTS 0
#define CPU_IS_BIG_ENDIAN 0
#define BSWAP(x) (ROL32((x), 8) & 0x00ff00ff | ROR32((x), 8) & 0xff00ff00)
#define BYTE_OFFSET(n) (n)

#define SELECT_BYTE_FROM_UINT32_IN_MEMORY 0
#if SELECT_BYTE_FROM_UINT32_IN_MEMORY
#define SELECT_BYTE(X, b) (((byte*)(&(X)))[BYTE_OFFSET(b)])
#else
#define SELECT_BYTE(X, b) (((X) >> (8 * (b))) & 0xff)
#endif

#define b0(X) SELECT_BYTE((X), 0)
#define b1(X) SELECT_BYTE((X), 1)
#define b2(X) SELECT_BYTE((X), 2)
#define b3(X) SELECT_BYTE((X), 3)

#if CONVERT_USING_CASTS
#define GET32(p) (*((uint32_t*)(p)))
#define PUT32(v, p) *((uint32_t*)(p)) = (v)
#else
#define GET32(p)                                                             \
  ((uint32_t)((p)[0]) | (uint32_t)((p)[1]) << 8 | (uint32_t)((p)[2]) << 16 | \
   (uint32_t)((p)[3]) << 24)
#define PUT32(v, p)                    \
  (p)[0] = (byte)(((v)) & 0xff);       \
  (p)[1] = (byte)(((v) >> 8) & 0xff);  \
  (p)[2] = (byte)(((v) >> 16) & 0xff); \
  (p)[3] = (byte)(((v) >> 24) & 0xff)

#endif

static const byte t_table[2][4][16] = {
    {{0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA,
      0x4},
     {0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9,
      0xD},
     {0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7,
      0x1},
     {0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC,
      0xA}},
    {{0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC,
      0x5},
     {0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0,
      0x8},
     {0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3,
      0xF},
     {0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8,
      0xA}}};

two_fish::two_fish() {
  direction_ = NONE;
  algorithm_.assign("twofish");
  initialized_ = false;
  key_size_in_bits_ = 0;
  key_ = nullptr;
}

two_fish::~two_fish() { memset((byte*)&round_data, 0, sizeof(round_data)); }

#define ROR4BY1(x) (((x) >> 1) | (((x) << 3) & 0x8))

static void make_q_table(const byte t[4][16], byte q[256]) {
  int ae, be, ao, bo;
  int i;
  for (i = 0; i < 256; i++) {
    ae = i >> 4;
    be = i & 0xf;
    ao = ae ^ be;
    bo = ae ^ ROR4BY1(be) ^ ((ae << 3) & 8);
    ae = t[0][ao];
    be = t[1][bo];
    ao = ae ^ be;
    bo = ae ^ ROR4BY1(be) ^ ((ae << 3) & 8);
    ae = t[2][ao];
    be = t[3][bo];
    q[i] = (byte)((be << 4) | ae);
  }
}

void two_fish::initialise_q_boxes() {
  make_q_table(t_table[0], q_table[0]);
  make_q_table(t_table[1], q_table[1]);
}

static const uint32_t mds_poly_divx_const[] = {0, 0xb4};

void two_fish::initialise_mds_tables() {
  int i;
  uint32_t q, qef, q5b;

  for (i = 0; i < 256; i++) {
    q = q_table[0][i];
    qef = (q >> 1) ^ mds_poly_divx_const[q & 1];
    q5b = (qef >> 1) ^ mds_poly_divx_const[qef & 1] ^ q;
    qef ^= q5b;
    MDS_table[1][i] = (q << 24) | (q5b << 16) | (qef << 8) | qef;
    MDS_table[3][i] = (q5b << 24) | (qef << 16) | (q << 8) | q5b;
    q = q_table[1][i];
    qef = (q >> 1) ^ mds_poly_divx_const[q & 1];
    q5b = (qef >> 1) ^ mds_poly_divx_const[qef & 1] ^ q;
    qef ^= q5b;
    MDS_table[0][i] = (qef << 24) | (qef << 16) | (q5b << 8) | q;
    MDS_table[2][i] = (qef << 24) | (q << 16) | (qef << 8) | q5b;
  }
}

#define q0 q_table[0]
#define q1 q_table[1]
#define H02(y, L) MDS_table[0][q0[q0[y] ^ L[8]] ^ L[0]]
#define H12(y, L) MDS_table[1][q0[q1[y] ^ L[9]] ^ L[1]]
#define H22(y, L) MDS_table[2][q1[q0[y] ^ L[10]] ^ L[2]]
#define H32(y, L) MDS_table[3][q1[q1[y] ^ L[11]] ^ L[3]]
#define H03(y, L) H02(q1[y] ^ L[16], L)
#define H13(y, L) H12(q1[y] ^ L[17], L)
#define H23(y, L) H22(q0[y] ^ L[18], L)
#define H33(y, L) H32(q0[y] ^ L[19], L)
#define H04(y, L) H03(q1[y] ^ L[24], L)
#define H14(y, L) H13(q0[y] ^ L[25], L)
#define H24(y, L) H23(q0[y] ^ L[26], L)
#define H34(y, L) H33(q1[y] ^ L[27], L)

uint32_t two_fish::h(int k, byte L[], int kCycles) {
  switch (kCycles) {
    case 2:
      return H02(k, L) ^ H12(k, L) ^ H22(k, L) ^ H32(k, L);
    case 3:
      return H03(k, L) ^ H13(k, L) ^ H23(k, L) ^ H33(k, L);
    case 4:
      return H04(k, L) ^ H14(k, L) ^ H24(k, L) ^ H34(k, L);
    default:
      return 0;
  }
}

void two_fish::fill_keyed_sboxes(byte S[], int kCycles, two_fishKey* xkey) {
  int i;

  switch (kCycles) {
    case 2:
      for (i = 0; i < 256; i++) {
	xkey->s[0][i] = H02(i, S);
	xkey->s[1][i] = H12(i, S);
	xkey->s[2][i] = H22(i, S);
	xkey->s[3][i] = H32(i, S);
      }
      break;
    case 3:
      for (i = 0; i < 256; i++) {
	xkey->s[0][i] = H03(i, S);
	xkey->s[1][i] = H13(i, S);
	xkey->s[2][i] = H23(i, S);
	xkey->s[3][i] = H33(i, S);
      }
      break;
    case 4:
      for (i = 0; i < 256; i++) {
	xkey->s[0][i] = H04(i, S);
	xkey->s[1][i] = H14(i, S);
	xkey->s[2][i] = H24(i, S);
	xkey->s[3][i] = H34(i, S);
      }
      break;
  }
}

static unsigned int rs_poly_const[] = {0, 0x14d};
static unsigned int rs_poly_div_const[] = {0, 0xa6};

void two_fish::init_key(int key_len, const byte key[], two_fishKey* xkey) {
  byte K[32 + 32 + 4];
  int kCycles;
  int i;
  uint32_t A, B;
  byte* kptr;
  byte* sptr;
  byte* t;
  byte b, bx, bxx;

  if (key_len < 0 || key_len > 32) {
    return;
  }
  memcpy(K, key, key_len);
  memset(K + key_len, 0, sizeof(K) - key_len);
  kCycles = (key_len + 7) >> 3;
  if (kCycles < 2) {
    kCycles = 2;
  }
  for (i = 0; i < 40; i += 2) {
    A = h(i, K, kCycles);
    B = h(i + 1, K + 4, kCycles);
    B = ROL32(B, 8);
    A += B;
    B += A;
    xkey->K[i] = A;
    xkey->K[i + 1] = ROL32(B, 9);
  }

  A = B = 0;
  kptr = K + 8 * kCycles;
  sptr = K + 32;
  while (kptr > K) {
    kptr -= 8;
    memset(sptr, 0, 4);
    memcpy(sptr + 4, kptr, 8);
    t = sptr + 11;
    while (t > sptr + 3) {
      b = *t;
      bx = (byte)((b << 1) ^ rs_poly_const[b >> 7]);
      bxx = (byte)((b >> 1) ^ rs_poly_div_const[b & 1] ^ bx);
      t[-1] ^= bxx;
      t[-2] ^= bx;
      t[-3] ^= bxx;
      t[-4] ^= b;
      t--;
    }
    sptr += 8;
  }
  b = bx = bxx = 0;
  fill_keyed_sboxes(&K[32], kCycles, xkey);
  memset(K, 0, sizeof(K));
}

bool two_fish::init(int key_bit_size, byte* key, int direction) {
  key_size_in_bits_= key_bit_size;
  algorithm_.assign("twofish");

  if (key == nullptr) {
    return false;
  }
  secret_.assign((char*)key, key_size_in_bits_ / NBITSINBYTE);
  key_ = (byte*) secret_.data();
  initialise_q_boxes();
  initialise_mds_tables();
  init_key(key_size_in_bits_ / NBITSINBYTE, key_, &round_data);
  initialized_ = true;
  direction_ = direction;
  return initialized_;
}

#define g0(X, xkey)                                            \
  (xkey->s[0][b0(X)] ^ xkey->s[1][b1(X)] ^ xkey->s[2][b2(X)] ^ \
   xkey->s[3][b3(X)])
#define g1(X, xkey)                                            \
  (xkey->s[0][b3(X)] ^ xkey->s[1][b0(X)] ^ xkey->s[2][b1(X)] ^ \
   xkey->s[3][b2(X)])

#define ENCRYPT_RND(A, B, C, D, T0, T1, xkey, r) \
  T0 = g0(A, xkey);                              \
  T1 = g1(B, xkey);                              \
  C ^= T0 + T1 + xkey->K[8 + 2 * (r)];           \
  C = ROR32(C, 1);                               \
  D = ROL32(D, 1);                               \
  D ^= T0 + 2 * T1 + xkey->K[8 + 2 * (r) + 1]
#define ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, r) \
  ENCRYPT_RND(A, B, C, D, T0, T1, xkey, 2 * (r));  \
  ENCRYPT_RND(C, D, A, B, T0, T1, xkey, 2 * (r) + 1)

/* Full 16-round encryption */
#define ENCRYPT(A, B, C, D, T0, T1, xkey)     \
  ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 0); \
  ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 1); \
  ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 2); \
  ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 3); \
  ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 4); \
  ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 5); \
  ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 6); \
  ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 7)

#define DECRYPT_RND(A, B, C, D, T0, T1, xkey, r) \
  T0 = g0(A, xkey);                              \
  T1 = g1(B, xkey);                              \
  C = ROL32(C, 1);                               \
  C ^= T0 + T1 + xkey->K[8 + 2 * (r)];           \
  D ^= T0 + 2 * T1 + xkey->K[8 + 2 * (r) + 1];   \
  D = ROR32(D, 1)

#define DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, r)    \
  DECRYPT_RND(A, B, C, D, T0, T1, xkey, 2 * (r) + 1); \
  DECRYPT_RND(C, D, A, B, T0, T1, xkey, 2 * (r))

/* Full 16-round decryption. */
#define DECRYPT(A, B, C, D, T0, T1, xkey)     \
  DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 7); \
  DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 6); \
  DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 5); \
  DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 4); \
  DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 3); \
  DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 2); \
  DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 1); \
  DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 0)

#define GET_INPUT(src, A, B, C, D, xkey, koff) \
  A = GET32(src) ^ xkey->K[koff];              \
  B = GET32(src + 4) ^ xkey->K[1 + koff];      \
  C = GET32(src + 8) ^ xkey->K[2 + koff];      \
  D = GET32(src + 12) ^ xkey->K[3 + koff]

#define PUT_OUTPUT(A, B, C, D, dst, xkey, koff) \
  A ^= xkey->K[koff];                           \
  B ^= xkey->K[1 + koff];                       \
  C ^= xkey->K[2 + koff];                       \
  D ^= xkey->K[3 + koff];                       \
  PUT32(A, dst);                                \
  PUT32(B, dst + 4);                            \
  PUT32(C, dst + 8);                            \
  PUT32(D, dst + 12)

void two_fish::encrypt_block(byte* p, byte* c) {
  volatile uint32_t A, B, C, D, T0, T1;
  const two_fishKey* xkey = &round_data;

  GET_INPUT(p, A, B, C, D, xkey, 0);
  ENCRYPT(A, B, C, D, T0, T1, xkey);
  PUT_OUTPUT(C, D, A, B, c, xkey, 4);
}

void two_fish::decrypt_block(byte* c, byte* p) {
  volatile uint32_t A, B, C, D, T0, T1;
  const two_fishKey* xkey = &round_data;

  GET_INPUT(c, A, B, C, D, xkey, 4);
  DECRYPT(A, B, C, D, T0, T1, xkey);
  PUT_OUTPUT(C, D, A, B, p, xkey, 0);
}

void two_fish::encrypt(int size, byte* p, byte* c) {
  volatile uint32_t A, B, C, D, T0, T1;
  const two_fishKey* xkey = &round_data;

  GET_INPUT(p, A, B, C, D, xkey, 0);
  ENCRYPT(A, B, C, D, T0, T1, xkey);
  PUT_OUTPUT(C, D, A, B, c, xkey, 4);
}

void two_fish::decrypt(int size, byte* c, byte* p) {
  volatile uint32_t A, B, C, D, T0, T1;
  const two_fishKey* xkey = &round_data;

  GET_INPUT(c, A, B, C, D, xkey, 4);
  DECRYPT(A, B, C, D, T0, T1, xkey);
  PUT_OUTPUT(C, D, A, B, p, xkey, 0);
}
