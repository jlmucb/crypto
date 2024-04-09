// Copyright 2014-2024, John Manferdelli, All Rights Reserved.
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
// File: kyber.cc

#include "crypto_support.h"
#include "kyber.h"
#include "sha3.h"

using namespace std;

// This is the "vanilla" kyber, which is slow and has
// large keys.

// For 256 bit seal (ML-KEM-1024)
//    n =256, q=3329, k=4, eta1=2, eta2=2, du=11, dv=5

kyber_parameters::kyber_parameters() {
}

kyber_parameters::~kyber_parameters() {
}

bool init_kyber(int ks) {
  if (ks == 256) {
    n_ = 256;
    q_ = 3329;
    k_ = 4;
    du_ = 11;
    dv_ = 5;
    dt_;
    eta1_ = 2;
    eta2_ = 2;
    beta_;
    return true;
  }
  return false;
}



// Compress(q,x,d)
//  closest((2^d/q)x), out in [0, 2^d-1)
int compress(int q, int x, int d) {
  int t = (1<<d) / q  * x; // fix
  return t;
}

// Decompress(q, x, d)
//  closest((q/2^d)x)

//  x' = Decompress(q, Compress(q, x, d), d)
//  |x'-x| <= B_q = cloasest(q/2^(d+1))

// Hard problem
//  distinguish between (a_i,b_i) := R_q^k x R_q and b_i = a_^Ts+e_i

// Keygen
//    A := R_q^(kxk), (s,e) := beta_eta^k x beta_eta^k
//    t := Compress(q,As+e), d_t)
//    pk := (A,t), sk := s

// G: {0,1}* --> {0,1}^512
// H: {0, 1}* --> {0,1}^256

// Kyber.Enc
//  r := {0,1}^256
//  t := Decompress(q, t, dt)
//  (e1, e2) := beta_eta^k x beta_eta^k
//  u := Compress(q, A^T r +e1, du)
//  v := Compress(q,t^tr + e2 + closest(q/2)n, dv)
//  return c=(u,v)

// Kyber.Dec
//  u := Decompress(q, u, du)
//  v := Decompress(q, v, dv)
//  return (v-s^Tu, 1)

// Kyber.Encaps
//  m := {0,1}^256
//  (K, r) := G(H(pk), m)
//  (u,v) := Kyber.Enc(A, t, m, r)
//  c := (u,v)
//  K := H(K, H(c))
//  return c,k

// Kyber.Decaps
//  m' := Kyber.Dec(s, u, v)
//  (K', r') := G(H(pk), m')
//  (u', v') := Kyber.Enc(A,t,m',r')
//  if (u', v') == (u, v)
//    K := H(K^', H(c))
//  else
//    K := H(Z, H(c))
//  return K



