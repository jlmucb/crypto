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

int round(int a, int b) {
  double t = ((double)a)/((double) b);
  t += 1.0 /2.0;
  return (int)t;
}

//  closest((2^d/q)x), out in [0, 2^d-1)
int compress(int q, int x, int d) {
  return round(x * (1<<d), q);
}

int decompress(int q, int x, int d) {
  return round(x * q, (1<<d));
}

kyber_parameters::kyber_parameters() {
}

kyber_parameters::~kyber_parameters() {
}

bool kyber_parameters::init_kyber(int ks) {
  if (ks == 256) {
    n_ = 256;
    q_ = 3329;
    k_ = 4;
    gamma_ = 17;
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

//  x' = Decompress(q, Compress(q, x, d), d)
//  |x'-x| <= B_q = cloasest(q/2^(d+1))

short_coefficient_vector::short_coefficient_vector(int q, int len) {
  q_ = q;
  len_ = len;

  c_.resize(len, 0);
  for (int i = 0; i < len; i++)
    c_[i] = 0;
}

short_coefficient_vector::~short_coefficient_vector() {
}

bool short_coefficient_add(short_coefficient_vector& in1, short_coefficient_vector& in2,
    short_coefficient_vector* out) {
  if (in1.c_.size() != in2.c_.size() || out->c_.size() < in1.c_.size())
    return false;
  for (int i = 0; i < (int)in1.c_.size(); i++) {
      out->c_[i] = (in1.c_[i] + in2.c_[i]) % in1.q_;
  }
  return true;
}

int short_reduce(short int a, short int b, short int q) {
  return (q + a - b) % q;
}

bool short_coefficient_mult(short_coefficient_vector& in1, short_coefficient_vector& in2,
    short_coefficient_vector* out) {
  // multiply and reduce by (x**in1.c_.size() + 1)
  if (in1.c_.size() != in2.c_.size() || out->c_.size() <  in2.c_.size()) {
    printf("Size mismatch\n");
    return false;
  }

  if (!short_coefficient_vector_zero(out))
    return false;
  vector<short int> t_out;
  t_out.resize(2 * in1.c_.size() - 1);
  for (int i = 0; i < (int)t_out.size(); i++)
    t_out[i] = 0;

  for (int i = 0; i < (int)in1.c_.size(); i++) {
    for (int j = 0; j < (int)in2.c_.size(); j++) {
      int32_t tt = (int64_t)in1.c_[i] * (int64_t)in2.c_[j];
      tt %= in1.q_;
      t_out[i + j] += (int) tt;
    }
  }

    int m = (int)in1.c_.size() - 1;
    for (int j = (2 * m); j > m; j--) {
      t_out[j -  m - 1] = short_reduce(t_out[j - m - 1], t_out[j], in1.q_);
    }

  for (int j = 0; j < (int)in1.c_.size(); j++) {
    if (t_out[j] >= 0)
      out->c_[j] = t_out[j] % in1.q_;
    else
      out->c_[j] = (in1.q_ + t_out[j]) % in1.q_;
  }
  return true;
}

void print_short_coefficient_vector(short_coefficient_vector& v) {
  if (v.c_.size() == 0)
    return;
  int k = (int)v.c_.size() - 1;
  while (v.c_[k] == 0 && k > 0)
    k--;
  if (k > 0)
    printf("(%d[%d] + ", v.c_[k], k);
  else
    printf("(");
  for (int i = k - 1; i > 0; i--) {
    printf("%d[%d] + ", v.c_[i], i);
    if ((i%8) ==0)
      printf("\n  ");
  }
  printf("%d[%d])\n", v.c_[0], 0);
}

bool short_coefficient_set_vector(short_coefficient_vector& in,
    short_coefficient_vector* out) {
    out->len_ = in.len_;
  out->c_.resize(in.c_.size());
  for (int j = 0; j < (int)out->len_; j++) {
    out->c_[j]= in.c_[j];
  }
  return true;
}

bool short_coefficient_vector_zero(short_coefficient_vector* out) {
  for (int j = 0; j < (int)out->len_; j++) {
    out->c_[j]= 0;
  }
  return true;
}

bool short_coefficient_vector_add_to(short_coefficient_vector& in,
      short_coefficient_vector* out) {
    if (in.len_ != out->len_)
    return false;
  for (int i = 0; i < in.len_; i++) {
      out->c_[i] += in.c_[i];
      out->c_[i] %= in.q_;
  }
  return true;
}

bool short_coefficient_equal(short_coefficient_vector& in1, short_coefficient_vector& in2) {
  if (in1.len_ != in2.len_)
    return false;

  for (int i = 0; i < in1.len_; i++) {
    if (in1.c_[i] != in2.c_[i])
      return false;
  }
  return true;
}

coefficient_vector::coefficient_vector(int q, int dim) {
  q_ = q;
  len_ = dim;

  c_.resize(dim, 0);
  for (int i = 0; i < dim; i++)
    c_[i] = 0;
}

coefficient_vector::~coefficient_vector() {
}

bool coefficient_equal(coefficient_vector& in1, coefficient_vector& in2) {
  if (in1.len_ != in2.len_)
    return false;

  for (int i = 0; i < in1.len_; i++) {
    if (in1.c_[i] != in2.c_[i])
      return false;
  }

  return true;
}

bool coefficient_add(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out) {
  if (in1.c_.size() != in2.c_.size() || out->c_.size() < in1.c_.size())
    return false;
  for (int i = 0; i < (int)in1.c_.size(); i++) {
      out->c_[i] = (in1.c_[i] + in2.c_[i]) % in1.q_;
  }
  return true;
}

int reduce(int a, int b, int q) {
  return (q + a - b) % q;
}

bool coefficient_mult(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out) {
  // multiply and reduce by (x**in1.c_.size() + 1)
  if (in1.c_.size() != in2.c_.size() || out->c_.size() <  in2.c_.size()) {
    printf("Size mismatch\n");
    return false;
  }

  if (!coefficient_vector_zero(out))
    return false;
  vector<int> t_out;
  t_out.resize(2 * in1.c_.size() - 1);
  for (int i = 0; i < (int)t_out.size(); i++)
    t_out[i] = 0;

  for (int i = 0; i < (int)in1.c_.size(); i++) {
    for (int j = 0; j < (int)in2.c_.size(); j++) {
      int64_t tt = (int64_t)in1.c_[i] * (int64_t)in2.c_[j];
      tt %= in1.q_;
      t_out[i + j] += (int) tt;
    }
  }

    int m = (int)in1.c_.size() - 1;
    for (int j = (2 * m); j > m; j--) {
      t_out[j -  m - 1] = reduce(t_out[j - m - 1], t_out[j], in1.q_);
    }

  for (int j = 0; j < (int)in1.c_.size(); j++) {
    if (t_out[j] >= 0)
      out->c_[j] = t_out[j] % in1.q_;
    else
      out->c_[j] = (in1.q_ + t_out[j]) % in1.q_;
  }

  return true;
}

bool coefficient_set_vector(coefficient_vector& in, coefficient_vector* out) {
  out->len_ = in.len_;
  out->c_.resize(in.c_.size());
  for (int j = 0; j < (int)out->len_; j++) {
    out->c_[j]= in.c_[j];
  }
  return true;
}

bool coefficient_vector_zero(coefficient_vector* out) {
  for (int j = 0; j < (int)out->len_; j++) {
    out->c_[j]= 0;
  }
  return true;
}

bool coefficient_vector_add_to(coefficient_vector& in, coefficient_vector* out) {
  if (in.len_ != out->len_)
    return false;
  for (int i = 0; i < in.len_; i++) {
      out->c_[i] += in.c_[i];
      out->c_[i] %= in.q_;
  }
  return true;
}

module_vector::module_vector(int q, int n, int dim) {
  q_ = q;
  n_ = n;
  dim_ = dim;
  c_ = new coefficient_vector* [dim];
  for (int i = 0; i < dim; i++)
    c_[i] = new coefficient_vector(q, n);
}

module_vector::~module_vector() {
  for (int i = 0; i < dim_; i++) {
    delete c_[i];
    c_[i] = nullptr;
  }
  if (c_ != nullptr)
    delete []c_;
  c_ = nullptr;
}

module_array::module_array(int q, int n, int nr, int nc) {
  q_ = q;
  n_ = n;
  nr_ = nr;
  nc_ = nc;

  c_ = new coefficient_vector* [nr * nc];
  for (int r = 0; r < nr_; r++) {
    for (int c = 0; c < nc_; c++) {
      c_[index(r,c)] = new coefficient_vector(q, n);
    }
  }
}

module_array::~module_array() {
  for (int r = 0; r < nr_; r++) {
    for (int c = 0; c < nc_; c++) {
      delete c_[index(r,c)];
      c_[index(r,c)] = nullptr;
    }
  }
  delete []c_;
  c_ = nullptr;
}

bool module_vector_add(module_vector& in1, module_vector& in2, module_vector* out) {
  if (in1.dim_ != in2.dim_ || in1.dim_ != out->dim_)
    return false;
  for (int i = 0; i < (int)in1.dim_; i++) {
      if (!coefficient_add(*in1.c_[i], *in2.c_[i], out->c_[i]))
        return false;
  }
  return true;
}

// out = in1 - in2
bool module_vector_subtract(module_vector& in1, module_vector& in2, module_vector* out) {
  if (in1.dim_ != in2.dim_ || in1.dim_ != out->dim_)
    return false;
  module_vector neg_in2(in2.q_, in2.n_, in2.dim_);
  for (int i = 0; i < in2.dim_; i++) {
    for (int j = 0; j < in2.n_; j++) {
      int t = in2.c_[i]->c_[j];
      if (t < 0)
        neg_in2.c_[i]->c_[j] = (-t) % in2.q_;
      else
        neg_in2.c_[i]->c_[j] = in2.q_ - (t % in2.q_);
    }
  }
  return module_vector_add(in1, neg_in2, out);
}

bool module_apply_array(module_array& A, module_vector& v, module_vector* out) {
  if ((A.nc_ != v.dim_) || A.nr_ != out->dim_) {
    printf("mismatch, nc: %d, v: %d, nr: %d, out: %d\n", A.nc_,  v.dim_, A.nr_, out->dim_);
    return false;
  }

  coefficient_vector acc(v.q_, v.n_);
  coefficient_vector t(v.q_, v.n_);

  for (int i = 0; i < A.nr_; i++) {
    if (!coefficient_vector_zero(&acc))
      return false;
    for (int j = 0; j < v.dim_; j++) {
      if (!coefficient_vector_zero(&t))
        return false;
      if (!coefficient_mult(*A.c_[A.index(i,j)], *v.c_[j], &t))
        return false;
      if (!coefficient_vector_add_to(t, &acc))
        return false;
    }
    if (!coefficient_set_vector(acc, out->c_[i]))
      return false;
  }
  return true;
}

int module_array::index(int r, int c) {
  return r * nc_ + c;
}

void print_module_array(module_array& ma) {
  for (int r = 0; r < ma.nr_; r++) {
    for (int c = 0; c < ma.nc_; c++) {
      printf("A[%d, %d] = ", r + 1, c + 1);
      print_coefficient_vector(*ma.c_[ma.index(r, c)]);
    }
  }
  printf("\n");
}

void print_module_vector(module_vector& mv) {
  for (int i = 0; i < (int)mv.dim_; i++) {
    printf("[%d] = ", i);
    print_coefficient_vector(*mv.c_[i]);
  }
  printf("\n");
}

void print_kyber_parameters(kyber_parameters& p) {
  printf("q: %d\n", p.q_);
  printf("n: %d\n", p.n_);
  printf("gamma: %d\n", p.gamma_);
  printf("k: %d\n", p.k_);
  printf("du: %d\n", p.du_);
  printf("dv: %d\n", p.dv_);
  printf("dt: %d\n", p.dt_);
  printf("eta1: %d\n", p.eta1_);
  printf("eta2: %d\n", p.eta2_);
  printf("beta: %d\n", p.beta_);
}

void print_coefficient_vector(coefficient_vector& v) {
  if (v.c_.size() == 0)
    return;
  int k = (int)v.c_.size() - 1;
  while (v.c_[k] == 0 && k > 0)
    k--; 
  if (k > 0)
    printf("(%d[%d] + ", v.c_[k], k);
  else
    printf("(");
  for (int i = k - 1; i > 0; i--) {
    printf("%d[%d] + ", v.c_[i], i);
    if ((i%8) ==0)
      printf("\n  ");
  }
  printf("%d[%d])\n", v.c_[0], 0);
}

int inf_norm(vector<int> v) {
  int x = abs(v[0]);

  for (int i = 1; i < (int)v.size(); i++) {
    if (abs(v[i]) > x)
        x = abs(v[i]);
  }
  return x;
}

int module_inf_norm(module_vector& mv) {
  int max = 0;
  int m;

  for (int i = 0; i < mv.dim_; i++) {
    m = inf_norm(mv.c_[i]->c_);
    if (m > max)
      max = m;
  }
  return max;
}

byte bit_reverse(byte b) {
  byte r = 0;

  for (int i = 0; i < 8; i++) {
    byte bb = b&0x1;
    r = (r<<1) | bb;
    b >>= 1;
  }
  return r;
}

bool ntt_base_mult(short int q, short int g, int& in1, int& in2, int* out) {
  short int s1 = (short int) (in1 & 0xffff);
  short int s2 = (short int) ((in1>>16) & 0xffff);
  short int t1 = (short int) (in2 & 0xffff);
  short int t2 = (short int) ((in2>>16) & 0xffff);
  short int u1 = ((t1 * s1) % q + (g * t2 * s2) % q) % q;
  short int u2 = (s1 * t2 + t1 * s2) % q;
  *out = ((int) u2) << 16 | ((int) u1);
  return true;
}

bool ntt_base_add(short int q, short int g, int& in1, int& in2, int* out) {
  short int s1 = (short int) (in1 & 0xffff);
  short int s2 = (short int) ((in1>>16) & 0xffff);
  short int t1 = (short int) (in2 & 0xffff);
  short int t2 = (short int) ((in2>>16) & 0xffff);
  short int u1 = (t1 + s1) % q;
  short int u2 = (t2 + s2) % q;
  *out = ((int) u2) << 16 | ((int) u1);
  return true;
}

short int exp_in_ntt(short int q, short int e, short int base) {
  short int r = 1;
  short int t = base;

  for (int i = 0; i < 16; i++) {
    if ((e&0x1) != 0) {
      r = (r * t) %q;
    }
    t = (t * t) % q;
    e >>= 1;
  }
  return r;
}

byte bit_in_byte_stream(int k, int l, byte* b) {
  if ((k+7)/8 > l)
    return 0;
  byte t = b[k/8];
  return (t>>(k%8))&1;
}

bool sample_ntt(int q, int l, byte* b, short int* out) {
  int i = 0;
  int j = 0;

  while (j < 256) {
    short int d1 = b[i] + 256 * (b[i+1] % 16);
    short int d2 = (b[i+1] / 16) + 16 * b[i+2];
    if (d1 < q) {
      out[j] = d1;
      j++;
    }
    if (d2 < q && j < 256) {
      out[j] = d2;
    }
    i += 3;
  }

  return true;
}

bool sample_poly_cbd(int q, int eta, byte* b, int l, short int* out) {
  int t;

  for (int i = 0; i < 256; i++) {
    short int x = 0;
    for (int j = 0; j < eta; j++)
      x += (short int) bit_in_byte_stream(2*i*eta+j, l, b);
    short int y = 0;
    for (int j = 0; j < eta; j++)
      y += (short int) bit_in_byte_stream(2*i*eta+eta+j, l, b);
    out[i] = (q + x - y) % q;
  }
  return true;
}

short int read_ntt(vector<int> x, int m) {
  int t = m / 2;
  if ((m&1)==0)
    return (short int)x[t];
  else
    return (short int)(x[t]>>16);
}

void write_ntt(int m, short int y, vector<int>& x) {
  int t = m / 2;
  short int t1 = (short int) (x[m] & 0xffff);
  short int t2 = (short int) ((x[m]>>16) & 0xffff);
  if ((m&1)==0)
    t1 = y;
  else
    t2 = y;
  x[m] = ((int) t2) << 16 | (int) t1;
}

// ntt representation of f= f0 + f_1x + ... is
//   [ f mod (x^2-g^2Rev(0)+1, f mod (x^2-g^2Rev(1)+1,..., f mod (x^2-g^2Rev(127)+1) ]
bool ntt(short int g, coefficient_vector& in, coefficient_vector* out) {
  int k = 1;
  coefficient_set_vector(in, out);

  for (int l = 128; l >= 2; l /=2) {
    for (int s = 0; s < 256; s+= 2*l) {
      byte bb = bit_reverse((byte)k);
      bb >>= 1;
      short int z = exp_in_ntt((short int) in.q_, (short int) bb, g);
      k++;
      for (int j = 0; j < s + l; j++) {
        short int t = (z * read_ntt(out->c_, j+l)) % in.q_;
        write_ntt(j + l, (read_ntt(out->c_, j) - t) % in.q_, out->c_);
        write_ntt(j, (read_ntt(out->c_, j) + t) % in.q_, out->c_);
      }
    }
  }
  return true;
}

bool ntt_inv(short int g, coefficient_vector& in, coefficient_vector* out) {
  int k = 127;
  coefficient_set_vector(in, out);

  for (int l = 2; l <= 128; l *= 2) {
    for (int s = 0; s < 256; s += 2 * l) {
      byte bb = bit_reverse((byte)k);
      bb >>= 1;
      short int z = exp_in_ntt((short int) in.q_, (short int) bb, g);
      k--;
      for (int j = s; j < s + l; s += 2 * l) {
        short int t = read_ntt(out->c_, j);
        write_ntt(j, (t + read_ntt(out->c_, j + l)) % in.q_, out->c_); 
        write_ntt(j + l, (in.q_ + (z *  read_ntt(out->c_, j + l))  - t )% in.q_, out->c_); 
      }
    }
  }
  for (int i = 0; i < 256; i++) {
    out->c_[i] = (out->c_[i] * 3303) % in.q_;
  }
  return true;
}

bool ntt_add(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out) {
  return false;
}

bool ntt_mult(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out) {
  return false;
}

// Hard problem
//  distinguish between (a_i,b_i) := R_q^k x R_q and b_i = a_^Ts+e_i

// H(s) := SHA3-256(s)
// J(s) := SHAKE256(s, 32)
// G(s) := SHA3-512(s)

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
//  return c,K

// Kyber.Decaps
//  m' := Kyber.Dec(s, u, v)
//  (K', r') := G(H(pk), m')
//  (u', v') := Kyber.Enc(A,t,m',r')
//  if (u', v') == (u, v)
//    K := H(K^', H(c))
//  else
//    K := H(Z, H(c))
//  return K



