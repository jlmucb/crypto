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
class ntru {
public:
  int N_;
  int64_t p_;
  int64_t q_;
  int d1_;
  int d2_;
  int64_t* f_;
  int64_t* g_;
  int64_t* fp_;
  int64_t* fq_;
  int64_t* h_;

  ntru();
  ~ntru();

  bool init(int N, int64_t p, int64_t q, int d1, int d2);
  bool encode_msg();
  bool encrypt();
  bool decrypt();
  bool decode_msg();

  void debug_set_parameters();
};

// gcd(a, b) = g, ax+by=g
bool int_gcd(int64_t a, int64_t b, int64_t* x, int64_t* y, int64_t* g) {
  return true;
}

// gcd(a, b) = g, ax+by=g
bool poly_gcd(int64_t* a, int64_t* b, int64_t* x, int64_t* y, int64_t* g) {
  return true;
}

bool poly_mult_mod_poly(int64_t modulus, int64_t* p, int64_t* f,
			int64_t* g, int64_t* r) {
  return true;
}

bool poly_add_mod_poly(int64_t modulus, int64_t* reducing_poly, int64_t* f,
		       int64_t* g, int64_t* r) {
  return true;
}

bool poly_inverse_mod_poly(int64_t modulus, int64_t* reducing_poly,
			   int64_t* f, int64_t* g, int64_t* r) {
  return true;
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

bool ntru::encrypt() {
  return true;
}

bool ntru::decrypt() {
  return true;
}

bool ntru::decode_msg() {
  return true;
}

void ntru::debug_set_parameters() {
}

