// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: ntru.cc

#include "crypto_support.h"
#include "lattice.h"

// R = Z[x]/(x^N-1), Rp = Zp[x]/(x^N-1)
// Parameters N, q, d, p 
//  q > (6d+1), (N, q) =1= (p,q), T(d1, d2): polys of deg < N, d1 equal to 1, d2 equal t0 -1, the rest 0
//  Message space: Rp 
//  Cipher space: Rq 
//  Key
//    f in T(d+1,d), g in T(d,d).  f fp = 1 (p), f fq = 1 (q), h=fq g (q)
//  Encrypt
//    m(x) is poly of deg <N coeff between -((p-1)/2) and ((p-1)/2)
//    PK (N, p, q, h) im Rp
//    sk = f
//    c = prh + m (q)
//  Decrypt
//    a = f c (q), a between -((p-1)/2) and ((p-1)/2)
//    m = fp a (p), a = f c = f(prh + m) (q)
//    coeff  at most p(2d) + (2d+1)p/2

// a >= b>0, a = bq+r
void euclid(int64_t a, int64_t b, int64_t* q, int64_t* r) {
  *q = a / b;
  *r = a - (b * (*q));
}

void move_up(int64_t* x, int64_t* y, int64_t* g) {
  x[0] = x[1];
  y[0] = y[1];
  g[0] = g[1];
  x[1] = x[2];
  y[1] = y[2];
  g[1] = g[2];
}

// gcd(a, b) = g, ax+by=g
//    Input: a >= b > 0
bool int_gcd(int64_t a, int64_t b, int64_t* x, int64_t* y, int64_t* g) {
  int64_t xc[3], yc[3], gc[3];
  int64_t q, r;

  // a x[i] + b y[i] = g[i]
  xc[0] = 1; yc[0] = 0; gc[0] = a;
  xc[1] = 0; yc[1] = 1; gc[1] = b;
 
  while(1) {
    euclid(gc[0], gc[1], &q, &r);
    if (r == 0) {
      *x = xc[1];
      *y = yc[1];
      *g = gc[1];
      return true;
    }
    xc[2] = xc[0] - q * xc[1];
    yc[2] = yc[0] - q * yc[1];
    gc[2] = gc[0] - q * gc[1];
    move_up(xc, yc, gc);
  }
  return true;
}

bool int_inverse(int64_t modulus, int64_t a, int64_t* inv) {
  int64_t x, y, g;

  if (!int_gcd(modulus, a, &x, &y, &g))
    return false;

  if ((g % modulus) != 1LL)
    return false;
  *inv = y;
  return true;
}

void print_poly(int n, int64_t* f) {
  int64_t* pint = f;

  printf("%lld + ", pint[0]);
  for (int i = 1; i < n; i++) {
    if (pint[i] != 0) {
      printf("%lld", pint[i]);
      printf(" x^%d +", i);
    }
  }
}

int poly_degree(int n, int64_t* f) {
  for (int i = (n-1); i >=0; i--)
    if (f[i] != 0)
      return i;
  return 0;
}

bool poly_zero(int n, int64_t* f) {
  for (int i = 0; i < n; i++)
    f[i] = 0ULL;
  return true;
}

bool poly_equal(int n, int64_t* f, int64_t* r) {
  for (int i = 0; i < n; i++) {
    if (f[i] != r[i])
      return false;
  }
  return true;
}

bool poly_copy(int n, int64_t* f, int64_t* r) {
  for (int i = 0; i < n; i++)
    r[i] = f[i];
  return true;
}

bool poly_add_mod_poly(int n, int64_t modulus, int64_t* f,
                       int64_t* g, int64_t* r) {
  for (int i = 0; i < n; i++) {
    r[i] = (f[i] + g[i]) % modulus;
    if (r[i] < 0)
      r[i] += modulus;
  }
  return true;
}

bool poly_mult_by_const(int n, int64_t modulus, int64_t d, int64_t* f,
                        int64_t* r) {
  for (int i = 0; i < n; i++) {
    r[i] = (d * f[i]) % modulus;
    if (r[i] < 0)
      r[i] += modulus;
  }
  return true;
}

bool poly_sub_mod_poly(int n, int64_t modulus, int64_t* f,
                       int64_t* g, int64_t* r) {
  for (int i = 0; i < n; i++) {
    r[i] = (f[i] - g[i]) % modulus;
    if (r[i] < 0)
      r[i] += modulus;
  }
  return true;
}

bool reduce(int64_t modulus, int m, int64_t* in, int n, int64_t* reducing_poly, int64_t* r) {

  // reducing poly must be monic
  int rd = poly_degree(n, reducing_poly);
  if (reducing_poly[rd] != 1)
    return false;

  int64_t in_temp[m];
  int64_t sub_temp[m];
  poly_zero(m, sub_temp);
  poly_zero(m, in_temp);
  poly_copy(m, in, in_temp);

  for (int i = (m-1); i >= rd; i--) {
    if (in_temp[i] == 0)
      continue;
    poly_zero(m, sub_temp);
    if (!poly_mult_by_const(n, modulus, in_temp[i], reducing_poly, &sub_temp[i - rd]))
      return false;
    if (!poly_sub_mod_poly(m, modulus, in_temp, sub_temp, in_temp))
      return false;
  }
  poly_copy(n, in_temp, r);
  return true;
}

bool poly_mult_mod_poly(int n, int64_t modulus, int64_t* f, int64_t* g, int64_t* r) {
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < n; j++) {
      r[i + j] = (r[i + j] + f[i] * g[j]) % modulus;
      if (r[i + j] < 0)
        r[i + j] += modulus;
    }
  }
  return true;
}

bool poly_mult_mod_poly_and_reduce(int n, int64_t modulus, int64_t* reducing_poly, int64_t* f,
                        int64_t* g, int64_t* r) {
  int64_t temp[2 * n];
  poly_zero(2 * n, temp);
  if (!poly_mult_mod_poly(n, modulus, f, g, temp))
    return false;
  return reduce(modulus, 2*n, temp, n, reducing_poly, r);
}

bool poly_div_step(int n, int64_t modulus, int64_t* a, int64_t* b, int64_t* q) {
  // let dm: degree(b) + dm = degree(a)
  // figure out coeff of x^dm p, c, so that degree(a - c x^dm) < degree(a),
  // put q = c x^dm

  int da = poly_degree(n, a);
  int db = poly_degree(n, b);
  int dm = da - db;
  int64_t d ;

  if (!int_inverse(modulus, b[db], &d))
    return false;
  if (d < 0)
    d += modulus;
  q[dm] = (d * a[da]) % modulus;
  if (q[dm] < 0)
    q[dm] += modulus;
  return true;
}

// deg(a) >= deg(b) > 0, a = bq+r
bool poly_euclid(int n, int64_t modulus, int64_t* a, int64_t* b, int64_t* q, int64_t* r) {
  if (poly_degree(n, a) < poly_degree(n, b))
    return false;
  int64_t temp_a[n];
  int64_t temp_b[2*n];
  int64_t temp_c[n];
  int64_t temp_q[n];
  poly_zero(n, q);
  poly_zero(n, r);
  poly_zero(n, temp_a);
  poly_zero(n, temp_q);
  poly_copy(n, a, temp_a);
  int k = n;

  while (poly_degree(n, temp_a) >= poly_degree(n, b) && k-- > 0) {
    poly_zero(n, temp_q);
    if (!poly_div_step(n, modulus, temp_a, b, temp_q))
      return false;
    if (!poly_add_mod_poly(n, modulus, q, temp_q, q))
      return false;
    poly_zero(2 * n, temp_b);
    if (!poly_mult_mod_poly(n, modulus, b, temp_q, temp_b))
      return false;
    if (!poly_sub_mod_poly(n, modulus, temp_a, temp_b, temp_c))
      return false;
    poly_zero(n, temp_a);
    poly_copy(n, temp_c, temp_a);
  }

  poly_zero(2 * n, temp_b);
  if (!poly_mult_mod_poly(n, modulus, b, q, temp_b))
    return false;
  if (!poly_sub_mod_poly(n, modulus, a, temp_b, r))
    return false;
      
  return true;
}

void poly_move_up(int n, int64_t** x, int64_t** y, int64_t** g) {
  int64_t* xp1 = &x[0][0];
  int64_t* yp1 = &y[0][0];;
  int64_t* gp1 = &g[0][0];
  int64_t* xp2 = &x[1][0];
  int64_t* yp2 = &y[1][0];;
  int64_t* gp2 = &g[1][0];

  for (int i = 0; i < n; i++) {
    *xp1 = *xp2;
    *yp1 = *yp2;
    *gp1 = *gp2;
    xp1++; xp2++;
    yp1++; yp2++;
    gp1++; gp2++;
  }

  xp1 = &x[1][0];
  yp1 = &y[1][0];;
  gp1 = &g[1][0];
  xp2 = &x[2][0];
  yp2 = &y[2][0];;
  gp2 = &g[2][0];
  for (int i = 0; i < n; i++) {
    *xp1 = *xp2;
    *yp1 = *yp2;
    *gp1 = *gp2;
    xp1++; xp2++;
    yp1++; yp2++;
    gp1++; gp2++;
  }
}

// gcd(a, b) = g, ax+by=g
bool poly_gcd(int n, int64_t modulus, int64_t* a, int64_t* b, int64_t* x, int64_t* y, int64_t* g) {
  int64_t xc[3][n];
  int64_t yc[3][n];
  int64_t gc[3][n];

  poly_zero(n, xc[0]);
  poly_zero(n, xc[1]);
  poly_zero(n, xc[2]);
  poly_zero(n, yc[0]);
  poly_zero(n, yc[1]);
  poly_zero(n, yc[2]);
  poly_zero(n, gc[0]);
  poly_zero(n, gc[1]);
  poly_zero(n, gc[2]);
  xc[0][0] = 1LL;
  yc[0][0] = 0LL;
  xc[1][0] = 0LL;
  yc[1][0] = 1LL;
  poly_copy(n, a, gc[0]);
  poly_copy(n, b, gc[1]);

  int64_t q[n];
  int64_t r[n];
  int64_t temp[2*n];
  int k = 0;

  while(k++ < n) {
    if (!poly_euclid(n, modulus, gc[0], gc[1], q, r)) {
      printf("Fail 1\n");
      return false;
    }
    if (poly_degree(n, r) == 0) {
      poly_copy(n, xc[1], x);
      poly_copy(n, yc[1], y);
      poly_copy(n, gc[1], g);
      return true;
    }

    poly_zero(2*n, temp);
    if (!poly_mult_mod_poly(n, modulus, xc[1], q, temp)) {
      printf("Fail 2\n");
      return false;
    }
    if (!poly_sub_mod_poly(n, modulus, xc[0], temp, xc[2])) {
      return false;
    }
    poly_zero(2*n, temp);
    if (!poly_mult_mod_poly(n, modulus, yc[1], q, temp)) {
      printf("Fail 3\n");
      return false;
    }
    if (!poly_sub_mod_poly(n, modulus, yc[0], temp, yc[2])) {
      printf("Fail 4\n");
      return false;
    }
    poly_zero(2*n, temp);
    if (!poly_mult_mod_poly(n, modulus, gc[1], q, temp)) {
      printf("Fail 5\n");
      return false;
    }
    if (!poly_sub_mod_poly(n, modulus, gc[0], temp, gc[2])) {
      printf("Fail 6\n");
      return false;
    }
    poly_move_up(n, (int64_t**)xc, (int64_t**)yc, (int64_t**)gc);
  }
 
  return true;
}

bool poly_inverse_mod_poly(int n, int64_t modulus, int64_t* f,
                           int64_t* g, int64_t* r) {
  int64_t x[n];
  int64_t y[n];
  int64_t gcd[n];

  if (!poly_gcd(n, modulus, f, g, x, y, gcd))
    return false;
  if ((poly_degree(n, gcd) > 0) || (gcd[0] == 0))
    return false;
  int64_t d = 0;
  if (!int_inverse(modulus, gcd[0], &d))
    return false;
  return poly_mult_by_const(n, modulus, d, y, r);
}


ntru::ntru() {
}

ntru::~ntru() {
}

bool ntru::init(int N, int64_t p, int64_t q, int d1, int d2) {
  // set params
  // generate f
  // generate g
  // calculate fp, f fp = 1 (mod p)
  // calculate gp, f f1 = 1 (mod q)
  // calculate h= fq g
  return true;
}

bool ntru::encode_msg() {
  return true;
}

// r is random poly in T(d_, d_)
// c= prh + m (mod q_)
bool ntru::encrypt(int64_t* msg, int64_t* r, int64_t* c) {
  return true;
}

//  a = f c (mod q), -q/2 <= a <= q/2
//  m = fp a (mod p_)
bool ntru::decrypt(int64_t* c, int64_t* recovered) {
  return true;
}

bool ntru::decode_msg() {
  return true;
}

void ntru::debug_set_parameters(int64_t* f, int64_t* g, int64_t* fp, int64_t* fq, int64_t* h) {
}
