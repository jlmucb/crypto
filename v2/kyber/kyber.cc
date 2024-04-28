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
//    R_q = Z_q[x]/(x^n + 1)
//    17^128 = -1 (mod q)
//    x^n + 1 = prod_k=0^127 (x^2- 17^(2k+1))

int round(int a, int b) {
  double t = ((double)a)/((double) b);
  t += 1.0 /2.0;
  return (int)t;
}

//  closest((2^d/q)x), out in [0, 2^d-1)
int compress(int q, int x, int d) {
  return round(x * (1<<d), q);
}

//  x' = Decompress(q, Compress(q, x, d), d)
//  |x'-x| <= B_q = clasest(q/2^(d+1))
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
    eta1_ = 2;
    eta2_ = 2;
    return true;
  }
  return false;
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

coefficient_array::coefficient_array(int q, int nr, int nc) {
  q_ = q;
  nr_ = nr;
  nc_ = nc;
  a_ = new int[nr * nc];
}

coefficient_array::~coefficient_array() {
  if (a_ != nullptr) {
    delete []a_;
  }
  a_ = nullptr;
}

int coefficient_array::index(int r, int c) {
  return nc_ * r + c;
}

bool coefficient_apply_array(coefficient_array& A, coefficient_vector& v,
        coefficient_vector* out) {
  return false;
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

bool make_module_vector_zero(module_vector* v) {
  for( int i = 0; i < v->dim_; i++) {
      if (!coefficient_vector_zero(v->c_[i])) {
        return false;
      }
  }
  return true;
}

bool make_module_array_zero(module_array& B) {
  for( int i = 0; i < B.nr_; i++) {
    for( int j = 0; j < B.nc_; j++) {
      if (!coefficient_vector_zero(B.c_[B.index(i,j)])) {
        return false;
      }
    }
  }
  return true;
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

bool module_apply_transposed_array(module_array& A, module_vector& v, module_vector* out) {
  if ((A.nr_ != v.dim_) || A.nc_ != out->dim_) {
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
      if (!coefficient_mult(*A.c_[A.index(j,i)], *v.c_[j], &t))
        return false;
      if (!coefficient_vector_add_to(t, &acc))
        return false;
    }
    if (!coefficient_set_vector(acc, out->c_[i]))
      return false;
  }
  return true;
}


bool ntt_module_apply_array(int g, module_array& A, module_vector& v, module_vector* out) {
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
      if (!multiply_ntt(g, *A.c_[A.index(i,j)], *v.c_[j], &t)) {
        return false;
      }
      if (!coefficient_vector_add_to(t, &acc))
        return false;
    }
    if (!coefficient_set_vector(acc, out->c_[i]))
      return false;
  }
  return true;
}

bool ntt_module_apply_transposed_array(int g, module_array& A, module_vector& v, module_vector* out) {
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
      if (!multiply_ntt(g, *A.c_[A.index(j,i)], *v.c_[i], &t)) {
        return false;
      }
      if (!coefficient_vector_add_to(t, &acc))
        return false;
    }
    if (!coefficient_set_vector(acc, out->c_[i]))
      return false;
  }
  return true;
}

bool module_vector_dot_product(module_vector& in1, module_vector& in2,
        coefficient_vector* out) {

  if (!coefficient_vector_zero(out)) {
    return false;
  }
  for (int i = 0; i < in1.dim_; i++) {
      coefficient_vector t(in1.q_, in1.n_);
      if (!coefficient_vector_zero(&t)) {
        return false;
      }
      if (!coefficient_mult(*in1.c_[i], *in2.c_[i], &t)) {
        return false;
      }
      if (!coefficient_vector_add_to(t, out)) {
        return false;
      }
  }
  return true;
}

bool module_vector_dot_product_first_transposed(module_vector& in1,
        module_vector& in2, coefficient_vector* out) {

  if (!coefficient_vector_zero(out)) {
    return false;
  }
  for (int i = 0; i < in1.dim_; i++) {
      coefficient_vector t(in1.q_, in1.n_);
      if (!coefficient_vector_zero(&t)) {
        return false;
      }
      if (!coefficient_mult(*in1.c_[in1.dim_ - 1 -i], *in2.c_[i], &t)) {
        return false;
      }
      if (!coefficient_vector_add_to(t, out)) {
        return false;
      }
  }
  return true;
}

bool ntt_module_vector_dot_product(module_vector& in1, module_vector& in2,
        coefficient_vector* out) {

  if (!coefficient_vector_zero(out)) {
    return false;
  }
  for (int i = 0; i < in1.dim_; i++) {
      coefficient_vector t(in1.q_, in1.n_);
      if (!coefficient_vector_zero(&t)) {
        return false;
      }
      if (!multiply_ntt(17, *in1.c_[i], *in2.c_[i], &t)) {
        return false;
      }
      if (!coefficient_vector_add_to(t, out)) {
        return false;
      }
  }
  return true;
}

bool ntt_module_vector_dot_product_first_transposed(module_vector& in1,
        module_vector& in2, coefficient_vector* out) {

  if (!coefficient_vector_zero(out)) {
    return false;
  }
  for (int i = 0; i < in1.dim_; i++) {
      coefficient_vector t(in1.q_, in1.n_);
      if (!coefficient_vector_zero(&t)) {
        return false;
      }
      if (!multiply_ntt(17, *in1.c_[in1.dim_ - 1 - i], *in2.c_[i], &t)) {
        return false;
      }
      if (!coefficient_vector_add_to(t, out)) {
        return false;
      }
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
  printf("eta1: %d\n", p.eta1_);
  printf("eta2: %d\n", p.eta2_);
  // printf("beta: %d\n", p.beta_);
  // printf("dt: %d\n", p.dt_);
}

void print_coefficient_vector(coefficient_vector& v) {
  int num_printed = 0;

  if (v.c_.size() == 0)
    return;

  int k = (int)v.c_.size() - 1;
  while (v.c_[k] == 0 && k > 0)
    k--; 
  if (k > 0) {
    printf("(%d[%d] + ", v.c_[k], k);
    num_printed++;
  }
  else
    printf("(");

  for (int i = k - 1; i > 0; i--) {
    if (v.c_[i] == 0)
      continue;
    printf("%d[%d] + ", v.c_[i], i);
    num_printed++;
    if ((num_printed%8) ==0)
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

bool ntt_base_mult(int q, int zeta, int& in1a, int& in1b,
        int& in2a, int& in2b, int* outa, int* outb) {
  int u1 = ((in1a * in2a) % q + (((in1b * in2b) % q) * zeta) % q) % q;
  int u2 = (((in1a * in2b) % q) + ((in2a * in1b) % q)) % q;
  *outa = u1;
  *outb = u2;
  return true;
}

int exp_in_ntt(int q, int e, int base) {
  int r = 1;
  int t = base;

  for (int i = 0; i < 16; i++) {
    if ((e&0x1) != 0) {
      r = (r * t) % q;
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

// l is 256
// b_len is 384
bool sample_ntt(int q, int l, int b_len, byte* b, vector<int>& out) {

  int i = 0;
  int j = 0;
  int loop = 0;

  for (int k = 0; k < l; k++)
    out[k] = 0; 

  if (b_len < 384) {
    printf("sample_ntt: byte input too small %d\n", b_len);
    return false;
  }

  while (j < l) {
    int d1 = ((int)b[i]) + 256 * (((int)b[i+1]) % 16);
    int d2 = (((int)b[i+1]) / 16) + 16 * ((int)b[i+2]);
// FIX
d1 %= q;
d2 %= q;
    if (d1 < q) {
      out[j] = d1;
      j++;
    }
    if (d2 < q && j < l) {
      out[j] = d2;
      j++;
    }
    i += 3;
    if (loop++ > 512)
      return false;
  }
  return true;
}

// random input bytes are 64*eta bytes long
// output is always 256 ints
bool sample_poly_cbd(int q, int eta, int b_len, byte* b,
        vector<int>& out) {

  int l = 64 * eta;
  if (b_len < l) {
    printf("sample_poly_cbd: bit array too small\n");
    return false;
  }

  for (int i = 0; i < 256; i++) {
    int x = 0;
    int y = 0;
    for (int j = 0; j < eta; j++) {
      x += bit_in_byte_stream(2 * i * eta + j, l, b);
      y += bit_in_byte_stream(2 * i * eta + eta + j, l, b);
    }
    out[i] = (x + eta - y) % eta;
  }
  return true;
}

// ntt representation of f= f0 + f_1x + ... is
//   [ f mod (x^2-g^2Rev(0)+1, f mod (x^2-g^2Rev(1)+1,..., f mod (x^2-g^2Rev(127)+1) ]
bool ntt(int g, coefficient_vector& in, coefficient_vector* out) {
  if (in.len_ != 256 || out->len_ != 256)
    return false;

  int k = 1;
  coefficient_set_vector(in, out);

  for (int l = 128; l >= 2; l /= 2) {
    for (int s = 0; s < in.len_; s+= 2 * l) {
      byte bb = bit_reverse((byte)k);
      bb >>= 1;
      int z = exp_in_ntt(in.q_, (int) bb, g);
      k++;
      for (int j = s; j < (s + l); j++) {
        int t = (z * out->c_[j + l]) % in.q_;
        int s1 = (out->c_[j] + (in.q_ - t)) % in.q_;
        out->c_[j + l]= s1;
        int s2 = (out->c_[j] + t) % in.q_;
        out->c_[j] = s2; 
      }
    }
  }
  return true;
}

bool ntt_inv(int g, coefficient_vector& in, coefficient_vector* out) {
  if (in.len_ != 256 || out->len_ != 256)
    return false;

  int k = 127;
  coefficient_set_vector(in, out);

  for (int l = 2; l <= 128; l *= 2) {
    for (int s = 0; s < 256; s += 2 * l) {
      byte bb = bit_reverse((byte)k);
      bb >>= 1;
      int z = exp_in_ntt(in.q_, (int)bb, g);
      k--;
      for (int j = s; j < s + l; j++) {
        int t = out->c_[j];
        int s1 = (t + out->c_[j+l]) % in.q_;
        out->c_[j] = s1;
        int s2 = (z *  (out->c_[j + l] + in.q_ - t)) % in.q_;
        out->c_[j + l] = s2;
      }
    }
  }
  for (int i = 0; i < 256; i++) {
    out->c_[i] = (out->c_[i] * 3303) % in.q_;
  }
  return true;
}

bool multiply_ntt(int g, coefficient_vector& in1, coefficient_vector& in2,
    coefficient_vector* out) {
  int zeta;
  for (int j = 0; j < in1.len_; j += 2) {
    int k =((int) bit_reverse((j/2)) >> 1);
    k = 2 * k + 1;
    zeta = exp_in_ntt(in1.q_, k, g);
    if (!ntt_base_mult(in1.q_, zeta, in1.c_[j], in1.c_[j + 1],
          in2.c_[j], in2.c_[j + 1],
          &(out->c_[j]), &(out->c_[j + 1]))) {
      return false;
    }
  }
  return true;
}

bool fill_random_coefficient_array(coefficient_array* ma) {
  for (int r = 0; r < ma->nr_; r++) {
    for (int c = 0; c < ma->nc_; c++) {
      int s = 0;
      int l = crypto_get_random_bytes(3, (byte*)&s);
      s %= ma->q_;
      ma->a_[ma->index(r, c)] = s;
    }
  }
  return true;
}

bool rand_coefficient(int top, coefficient_vector& v) {
  for (int k = 0; k < (int)v.c_.size(); k++) {
    int s = 0;
    int m = crypto_get_random_bytes(3, (byte*)&s);
    s %= top;
    v.c_[k] = s;
  }
  return true;
}

bool fill_random_module_array(module_array* ma) {
  for (int r = 0; r < ma->nr_; r++) {
    for (int c = 0; c < ma->nc_; c++) {
      for (int j = 0; j < ma->n_; c++) {
        int s = 0;
        int l = crypto_get_random_bytes(3, (byte*)&s);
        s %= ma->q_;
        ma->c_[ma->index(r, c)]->c_[j] = s;
      }
    }
  }
  return true;
}

bool rand_module_coefficients(int top, module_vector& v) {
  for (int k = 0; k < (int)v.dim_; k++) {
    for (int j = 0; j < v.n_; j++) {
      int s = 0;
      int m = crypto_get_random_bytes(3, (byte*)&s);
      s %= top;
      v.c_[k]->c_[j] = s;
    }
  }
  return true;
}

// Hard problem
//  distinguish between (a_i,b_i) := R_q^k x R_q and b_i = a_^Ts+e_i

// G: {0,1}* --> {0,1}^512
// H: {0, 1}* --> {0,1}^256
// H(s) := SHA3-256(s)
// J(s) := SHAKE256(s, 32)
//
// PRF(eta)(s, b) := SHAKE256(s||b, 64 · eta),
// XOF(ρ, i, j) := SHAKE128(ρ||i|| j)

// G(s) := SHA3-512(s)
bool G(int in_len, byte* in, int bit_out_len, byte* out) {
  sha3 h;

  if (!h.init(512, bit_out_len)) {
    return false;
  }
  h.add_to_hash(in_len, in);
  h.finalize();
  if (!h.get_digest(((bit_out_len + NBITSINBYTE - 1) / NBITSINBYTE), out)) {
    return false;
  }
  return true;
}

// PRF(eta)(s, b) := SHAKE256(s||b, 64 · eta),
bool prf(int eta, int in1_len, byte* in1, int in2_len, byte* in2, int bit_out_len, byte* out) {
  sha3 h;

  if (!h.init(512, bit_out_len)) {
    printf("prf init failed\n");
    return false;
  }
  h.add_to_hash(in1_len, in1);
  h.add_to_hash(in2_len, in2);
  h.shake_finalize();
  if (!h.get_digest((bit_out_len + NBITSINBYTE - 1) / NBITSINBYTE, out)) {
    printf("prf failed\n");
    return false;
  }
  return true;
}

// XOF(ρ, i, j) := SHAKE128(ρ||i|| j)
bool xof(int in1_len, byte* in1, int i, int j, int bit_out_len, byte* out) {
  sha3 h;

  if (!h.init(256)) {
    printf("xof init failed %d\n", bit_out_len);
    return false;
  }
  h.add_to_hash(in1_len, in1);
  h.add_to_hash(sizeof(int), (byte*)&i);
  h.add_to_hash(sizeof(int), (byte*)&j);
  h.shake_squeeze_finalize();
  
  int bytes_to_go = (bit_out_len + NBITSINBYTE - 1) / NBITSINBYTE;
  int bytes_out_so_far = 0;
  while (bytes_to_go > 0) {
    int size = bytes_to_go;
    if (bytes_to_go > h.rb_)
      size = h.rb_;
    memcpy(&out[bytes_out_so_far], h.state_, size);
    bytes_to_go -= size;
    bytes_out_so_far += size;
    h.squeeze();
  }
  return true;
}

// least significant bit first
byte bit_from_ints(int bits_in_int, int bit_numb, int* pi) {
  int i = bit_numb / bits_in_int;
  int j =  bit_numb - (i * bits_in_int);
  int t = pi[i]>>j;
  byte b = t & 1;
  return b;
}

// least significant bit first
byte bit_from_int_vector(int bits_in_int, int bit_numb, vector<int>& v) {
  int i = bit_numb / bits_in_int;
  int j =  bit_numb - (i * bits_in_int);
  int t = v[i]>>j;
  byte b = t & 1;
  return b;
}

byte bit_from_bytes(int bit_numb, byte* buf) {
  int i = bit_numb / NBITSINBYTE;
  int j =  bit_numb - i * NBITSINBYTE;
  int b = buf[i]>>j;
  return b&1;
}

// encode n d-bit integers into byte array
bool byte_encode(int d, int n, int* pi, byte* out) {
  int num_bits = d * n;
  byte t = 0;
  byte r = 0;
  int k = 0;  // bit position in output byte
  int m = 0;  // current output byte number
  memset(out, 0, ((d * n) + NBITSINBYTE - 1) / NBITSINBYTE);
  for (int i = 0; i < num_bits; i++) {
    t = (int)bit_from_ints(d, i, pi);
    r |= t << k;
    if ((k % NBITSINBYTE)  == 7) {
      out[m++] = r;
      r = 0;
      k = 0;
    } else {
      k++;
    }
  }
  return true;
}

// decode byte array into n d-bit integers
bool byte_decode(int d, int n, int in_len, byte* in, int* pi) {
  int num_bits = d * n;
  int t = 0;
  int r = 0;
  int k = 0;  // bit position in int
  int m = 0;  // current output int
  memset((byte*)pi, 0, n * sizeof(int));
  for (int i = 0; i < num_bits; i++) {
    t = (int)bit_from_bytes(i, in);
    r |= t << k;
    if ((k % d)  == (d - 1)) {
      pi[m++] = r;
      r = 0;
      k = 0;
    } else {
      k++;
    }
  }
  return true;
}

// encode n d-bit integers into byte array
bool byte_encode_from_vector(int d, int n, vector<int>& v, byte* out) {
  int num_bits = d * n;
  byte t = 0;
  byte r = 0;
  int k = 0;  // bit position in output byte
  int m = 0;  // current output byte number
  int out_len = (num_bits + NBITSINBYTE - 1) / NBITSINBYTE;
  memset(out, 0, out_len);
  for (int i = 0; i < num_bits; i++) {
    t = (int)bit_from_int_vector(d, i, v);
    r |= t << k;
    if ((k % NBITSINBYTE)  == 7) {
      out[m++] = r;
      r = 0;
      k = 0;
    } else {
      k++;
    }
  }
  return true;
}

// decode byte array into n d-bit integers
bool byte_decode_to_vector(int d, int n, int in_len, byte* in, vector<int>& v) {
  int num_bits = d * n;
  int t = 0;
  int r = 0;
  int k = 0;  // bit position in int
  int m = 0;  // current output int
  for (int i = 0; i < num_bits; i++) {
    t = (int)bit_from_bytes(i, in);
    r |= t << k;
    if ((k % d)  == (d - 1)) {
      v[m++] = r;
      r = 0;
      k = 0;
    } else {
      k++;
    }
  }
  return true;
}


// Kyber.Keygen
//  abbreviated
//    A := R_q^(kxk), (s,e) := beta_eta^k x beta_eta^k
//    t := Compress(q,As+e), d_t)
//    pk := (A,t), sk := s
//
//  full
//    d := random32)
//    (rho, sigma) := G(d)
//    N := 0
//    for (i = 0 i < k; i++) {
//      for (j = 0; j < k; j++) {
//        A^[i,j] := sample_ntt(XOF(rho, i, j)
//      }
//    }
//    for (i = 0; i < k; i++) {
//      s[i] := sample_poly_cbd(eta1, PRF(eta1, sigma, N))
//      N++;
//    }
//    for (i = 0; i < k; i++) {
//      e[i] := sample_poly_cdb(eta1, PRF(eta1, sigma, rho))
//      n++
//    }
//    s^ := ntt(s)
//    e^ := ntt(e))
//    t^ := A^(s^)+e^
//    ek := byte_encode(12) (t^) || rho
//    dk := byte_encode(12) (s^)
//    return (ek, dk) [384k+32, 384k] bytes
bool kyber_keygen(int g, kyber_parameters& p, int* ek_len, byte* ek,
        int* dk_len, byte* dk) {

  byte d[32];
  byte parameters[64];  // (rho, sigma)
  memset(d, 0, 32);
  memset(parameters, 0, 64);

  int n_b = crypto_get_random_bytes(32, d);
  if (n_b != 32) {
    printf("kyber_keygen: crypto_get_random_bytes returne wrong nuber of bytes\n");
    return false;
  }
  if (!G(32, d, 512, parameters)) {
    printf("kyber_keygen: crypto_get_random_bytes failed\n");
    return false;
  }

  module_vector s(p.q_, p.n_, p.k_);                    // secret
  module_vector e(p.q_, p.n_, p.k_);                    // noise
  module_array A_ntt(p.q_, p.n_, p.k_, p.k_);           // ntt domain array
  module_vector e_ntt(p.q_, p.n_, p.k_);                // ntt domain noise
  module_vector s_ntt(p.q_, p.n_, p.k_);                // ntt domain secret
  module_vector t_ntt(p.q_, p.n_, p.k_);                // ntt domain public key (As+e)
  
  module_vector t(p.q_, p.n_, p.k_);
  module_vector r_ntt(p.q_, p.n_, p.k_);

  int N = 0;
  byte* rho = parameters;
  byte* sigma = &parameters[32];

  // Generate A_ntt
  for (int i = 0; i < p.k_; i++) {
    for (int j = 0; j < p.k_; j++) {
      int b_xof_len = 384;
      byte b_xof[b_xof_len];
      memset(b_xof, 0, b_xof_len);

      if (!xof(32, rho, i, j, b_xof_len * NBITSINBYTE, b_xof)) {
        printf("kyber_keygen: xof failed\n");
        return false;
      }

      if (!sample_ntt(p.q_, p.n_, b_xof_len, b_xof,
                      A_ntt.c_[A_ntt.index(i, j)]->c_)) {
        printf("kyber_keygen: sample_ntt failed\n");
        return false;
      }
    }
  }

  // Generate secret polynomial
  for (int i = 0; i < s.dim_; i++) {
    int b_prf_len = 64 * p.eta1_;
    byte b_prf[b_prf_len];
    memset(b_prf, 0, b_prf_len);

    if (!prf(p.eta1_, 32, sigma, sizeof(int), (byte*)&N,
          NBITSINBYTE * b_prf_len, b_prf)) {
       printf("kyber_keygen: prf (1) failed\n");
      return false;
    }
    if (!sample_poly_cbd(p.q_, p.eta1_, b_prf_len, b_prf, s.c_[i]->c_)) {
       printf("kyber_keygen: sample_poly_cdb (1) failed\n");
      return false;
    }
    N++;
  }

  // Generate noise
  for (int i = 0; i < e.dim_; i++) {
    int b_prf_len = 64 * p.eta1_;
    byte b_prf[b_prf_len];
    memset(b_prf, 0, b_prf_len);

    if (!prf(p.eta1_, 32, sigma, sizeof(int), (byte*)&N,
          NBITSINBYTE * b_prf_len, b_prf)) {
       printf("kyber_keygen: prf (2) failed\n");
      return false;
    }
    if (!sample_poly_cbd(p.q_, p.eta1_, b_prf_len, b_prf, e.c_[i]->c_)) {
       printf("kyber_keygen: sample_poly_cdb (1) failed\n");
      return false;
    }
    N++;
  }

  // Secret and noise to ntt domain
  for (int i = 0; i < s.dim_; i++) {
    if (!ntt(g, *s.c_[i], s_ntt.c_[i])) {
      return false;
    }
    if (!ntt(g, *e.c_[i], e_ntt.c_[i])) {
      return false;
    }
  }

  // Generate public key
  // t^ := A^(s^)+e^
  if (!make_module_vector_zero(&r_ntt)) {
    return false;
  }
  if (!make_module_vector_zero(&t_ntt)) {
    return false;
  }

  // Calculate t_ntt = A_ntt(s_ntt)+e_ntt
  if (!ntt_module_apply_array(g, A_ntt, s_ntt, &r_ntt)) {
    return false;
  }
  if (!module_vector_add(r_ntt, e_ntt, &t_ntt)) {
    printf("kyber_keygen: module_vector_add failed\n");
    return false;
  }

  byte* pek = ek;
  // ek := byte_encode(12) (t^) || rho
  for (int i = 0; i < t_ntt.dim_; i++) {
    if (!byte_encode_from_vector(12, p.n_, t_ntt.c_[i]->c_, pek)) {
      printf("kyber_keygen: byte_encode (2) failed\n");
      return false;
    }
    pek += 384;
  }
  memcpy(pek, rho, 32);
  *ek_len = t_ntt.dim_ * 384 + 32;

  // dk := byte_encode(12) (s^)
  byte* pdk = dk;
  for (int i = 0; i < s_ntt.dim_; i++) {
    if (!byte_encode_from_vector(12, p.n_, s_ntt.c_[i]->c_, pdk)) {
      printf("kyber_keygen: byte_encode (3) failed\n");
      return false;
    }
    pdk += 384;
  }
  *dk_len = s_ntt.dim_ * 384;

#if 1
  printf("\n\nKeygen\n\n");
  printf("d: ");
  print_bytes(32, d);
  printf("rho || sigma: ");
  print_bytes(64, parameters);
  printf("rho: ");
  print_bytes(32, parameters);
  printf("\n");
  printf("t_ntt (public key):");
  print_module_vector(t_ntt);
  printf("A_ntt:\n");
  print_module_array(A_ntt);
  printf("e (noise):\n");
  print_module_vector(e);
  printf("s (secret polynomial): \n");
  print_module_vector(s);
  printf("s_ntt:\n");
  print_module_vector(s_ntt);
  printf("r_ntt:\n");
  print_module_vector(r_ntt);
  printf("\n");

  // Compare s_ntt dot (A_ntt^T r_ntt) and r_ntt dot (A_ntt s_ntt)
  module_vector s1(p.q_, p.n_, p.k_);
  module_vector s2(p.q_, p.n_, p.k_);
  coefficient_vector r1(p.q_, p.n_);
  coefficient_vector r2(p.q_, p.n_);
  coefficient_vector r3(p.q_, p.n_);

  if (!ntt_module_apply_transposed_array(g, A_ntt, r_ntt, &s1)) {
    printf("test ntt_module_apply_transposed_array fail\n");
    return false;
  }
  if (!ntt_module_apply_array(g, A_ntt, s_ntt, &s2)) {
    printf("test ntt_module_apply_array fail\n");
    return false;
  }
  if (!module_vector_dot_product(s_ntt, s1, &r1)) {
    printf("test module_vector_dot_product (1) fail\n");
    return false;
  }
  if (!module_vector_dot_product(r_ntt, s2, &r2)) {
    printf("test module_vector_dot_product (3) fail\n");
    return false;
  }
  for (int j = 0; j < 256; j++) {
    r3.c_[j] = (p.q_ + r1.c_[j] - r1.c_[j]) % p.q_;
  }
  printf("COMPARISON test\n");
  print_coefficient_vector(r3);
  printf("\n");
#endif
  return true;
}

// Kyber.Encrypt
//  abbreviated
//    r := {0,1}^256
//    t := Decompress(q, t, dt)
//    (e1, e2) := noise
//    u := Compress(q, A^T r +e1, du)
//    v := Compress(q,t^tr + e2 + closest(q/2)n, dv)
//    return c=(u,v)
//  full
//    N := 0
//    t_ntt^ := byte_decode(12, ek[0:384k])
//    rho :=  bytedecode(12, ek[384k:384k_32]
//    for (i = 0; i < k; i++) {
//      for (j=0; j < k; j++) {
//        A^[i,j] := sample_ntt(xof(rho, i, j))
//      }
//    }
//    for (i = 0; i < k; i++) {
//      r[i] = sample_poly_cdb(eta1,(PRF(eta1, r, N)))
//      n++;
//    }
//    for (i = 0; i < k; i++) {
//      e1[i] = sample_poly_cdb(eta2,(PRF(eta2, r, N)))
//      n++;
//    }
//    e2 = sample_poly_cdb(eta2,(PRF(eta2, r, N)))
//    r^ = ntt(r)
//    u = ntt_inv(A^^T(r^) + e1
//    mu = decompress(1, byte_encode(1,u))
//    nu = ntt_inv(t^^T r^) +e2 + mu
//    c1 = byte_encode(du, compress(du,u)) [32(du * k)] bytes
//    c2 = byte_encode(dv, compress(dv,nu)) [32dv bytes]
//    return (c1, c2)
bool kyber_encrypt(int g, kyber_parameters& p, int ek_len, byte* ek,
      int m_len, byte* m, int b_r_len, byte* b_r, int* c_len, byte* c) {

  module_array A_ntt(p.q_, p.n_, p.k_, p.k_);   // A^ matrix
  module_vector t_ntt(p.q_, p.n_, p.k_);        // public key
  module_vector r(p.q_, p.n_, p.k_);            // noise vector generated fro, b_r
  module_vector r_ntt(p.q_, p.n_, p.k_);        // transfomed into ntt domain
  module_vector e1(p.q_, p.n_, p.k_);           // noise module vector
  module_vector u(p.q_, p.n_, p.k_);            // u (c1) as in spac
  coefficient_vector e2(p.q_, p.n_);            // noise

  // Recover public key
  byte* p_b = ek;
  for (int i = 0; i < t_ntt.dim_; i++) {
    if (!byte_decode_to_vector(12, p.n_, 384, p_b, t_ntt.c_[i]->c_)) {
      printf("kyber_encrypt: byte_decode_to_vector (1) failed\n");
      return false;
    }
    p_b += 384;
  }
 
  byte rho[32];
  memset(rho, 0, 32);
  memcpy(rho, p_b, 32);

  int N = 0;

  // Recover A_ntt
  for (int i = 0; i < p.k_; i++) {
    for (int j = 0; j < p.k_; j++) {
      int b_xof_len = 384;
      byte b_xof[b_xof_len];
      memset(b_xof, 0, b_xof_len);

      if (!xof(32, rho, i, j, b_xof_len * NBITSINBYTE, b_xof)) {
        printf("kyber_encrypt: xof failed\n");
        return false;
      }

      if (!sample_ntt(p.q_, p.n_, b_xof_len, b_xof,
                      A_ntt.c_[A_ntt.index(i, j)]->c_)) {
        printf("kyber_encrypt: sample_ntt failed\n");
        return false;
      }
    }
  }

  // Generate encryption randomness poly (r)
  for (int i = 0; i < r.dim_; i++) {
    int b_prf_len = 64 * p.eta1_;
    byte b_prf[b_prf_len];
    memset(b_prf, 0, b_prf_len);

    if (!prf(p.eta1_, 32, rho, sizeof(int), (byte*)&N,
          NBITSINBYTE * b_prf_len, b_prf)) {
      printf("kyber_encrypt: prf (1) failed\n");
      return false;
    }
    if (!sample_poly_cbd(p.q_, p.eta1_, b_prf_len, b_prf, r.c_[i]->c_)) {
        printf("kyber_encrypt: sample_poly_cdb (1) failed\n");
        return false;
      }
    N++;
  }
  // transform to ntt domain
  for (int i = 0; i < r.dim_; i++) {
    if (!ntt(g, *r.c_[i], r_ntt.c_[i])) {
        printf("kyber_encrypt: ntt (1) failed\n");
        return false;
      }
  }

  // Generate noise element (e1)
  for (int i = 0; i < e1.dim_; i++) {
    int b_prf_len = 64 * p.eta2_;
    byte b_prf[b_prf_len];
    memset(b_prf, 0, b_prf_len);

    if (!prf(p.eta2_, 32, rho, sizeof(int), (byte*)&N,
          NBITSINBYTE * b_prf_len, b_prf)) {
       printf("kyber_encrypt: prf (1) failed\n");
      return false;
    }
    if (!sample_poly_cbd(p.q_, p.eta2_, b_prf_len, b_prf, e1.c_[i]->c_)) {
        printf("kyber_encrypt: sample_poly_cdb (1) failed\n");
        return false;
      }
    N++;
  }

  // Generate noise element (e2)
  {
    int b_prf_len = 64 * p.eta2_;
    byte b_prf[b_prf_len];
    memset(b_prf, 0, b_prf_len);

    if (!prf(p.eta2_, 32, rho, sizeof(int), (byte*)&N,
          NBITSINBYTE * b_prf_len, b_prf)) {
       printf("kyber_encrypt: prf (1) failed\n");
      return false;
    }
    if (!sample_poly_cbd(p.q_, p.eta2_, b_prf_len, b_prf, e2.c_)) {
        printf("kyber_encrypt: sample_poly_cdb (1) failed\n");
        return false;
      }
    N++;
  }

  module_vector tmp1(p.q_, p.n_, p.k_);
  module_vector tmp2(p.q_, p.n_, p.k_);
  if (!make_module_vector_zero(&tmp1)) {
    return false;
  }
  if (!make_module_vector_zero(&tmp2)) {
    return false;
  }
  if (!make_module_vector_zero(&u)) {
    return false;
  }

  // Compute u = ntt_inv(A_ntt^T r_ntt) + e1
  if (!ntt_module_apply_transposed_array(g, A_ntt, r_ntt, &tmp1)) {
    printf("kyber_encrypt: ntt_module_apply_transpose_array) failed\n");
    return false;
  }
  for (int i = 0; i < p.k_; i++) {
    if (!ntt_inv(g, *tmp1.c_[i], tmp2.c_[i])) {
      return false;
    }
  }
  if (!module_vector_add(tmp2, e1, &u)) {
    printf("kyber_encrypt: module_vector_add failed\n");
    return false;
  }

  coefficient_vector mu(p.q_, p.n_);
  if (!coefficient_vector_zero(&mu)) {
      return false;
  }

  // Compute mu = decompress(1, byte_decode(m)), encoded message
  if (!byte_decode_to_vector(1, p.n_, m_len, m, mu.c_)) {
    return false;
  }
  for (int i = 0; i < p.n_; i++) {
    mu.c_[i] = decompress(p.q_, mu.c_[i], 1);
  }

  // compress and encode u (c1)
  module_vector compressed_u(p.q_, p.n_, p.k_);
  int c1_b_len = (p.du_ * p.n_ * p.k_) / NBITSINBYTE;
  byte b_c1[c1_b_len];
  byte* pp = b_c1;
  for (int i = 0; i < p.k_; i++) {
    for (int j = 0; j < p.n_; j++) {
      compressed_u.c_[i]->c_[j] = compress(p.q_, u.c_[i]->c_[j], p.du_);
    }
    if (!byte_encode_from_vector(p.du_, p.n_, compressed_u.c_[i]->c_, pp)) {
        return false;
    }
    int len = (p.du_ * p.n_) / NBITSINBYTE;
    pp += len;
  }

  // compress and encode nu = ntt_inv(t_ntt dot r_ntt) + e2 + mu
  coefficient_vector nu_ntt(p.q_, p.n_);
  coefficient_vector nu(p.q_, p.n_);
  if (!coefficient_vector_zero(&nu_ntt)) {
      return false;
  }
  if (!coefficient_vector_zero(&nu)) {
      return false;
  }
  if (!ntt_module_vector_dot_product(t_ntt, r_ntt, &nu_ntt)) {
      return false;
  }
  if (!ntt_inv(g, nu_ntt, &nu)) {
    return false;
  }
  if (!coefficient_vector_add_to(e2, &nu)) {
      return false;
  }
  if (!coefficient_vector_add_to(mu, &nu)) {
      return false;
  }

  // Compress and encode nu (c2)
  coefficient_vector compressed_nu(p.q_, p.n_);
  int c2_b_len = (p.dv_ * 256) / NBITSINBYTE;
  byte b_c2[c2_b_len];
  for (int j = 0; j < compressed_nu.len_; j++) {
    compressed_nu.c_[j] = compress(p.q_, nu.c_[j], p.dv_);
  }
  if (!byte_encode_from_vector(p.dv_, 256, compressed_nu.c_, b_c2)) {
    return false;
  }

  if (*c_len < (c1_b_len + c2_b_len)) {
    printf("kyber_encrypt: output too small\n");
    return false;
  }
  *c_len = c1_b_len + c2_b_len;
  memcpy(c, b_c1, c1_b_len);
  memcpy(&c[c1_b_len], b_c2, c2_b_len);

#if 1
  printf("\nEncrypt\n\n");
  printf("rho: ");
  print_bytes(32, rho);
  printf("\n");
  printf("t_ntt:\n");
  print_module_vector(t_ntt);
  printf("A_ntt:\n");
  print_module_array(A_ntt);
  printf("r:\n");
  print_module_vector(r);
  printf("r_ntt:\n");
  print_module_vector(r_ntt);
  printf("e1:\n");
  print_module_vector(e1);
  printf("e2:\n");
  print_coefficient_vector(e2);
  printf("\n");
  printf("u:\n");
  print_module_vector(u);
  printf("m: ");
  print_bytes(m_len, m);
  printf("\n");
  printf("mu:\n");
  print_coefficient_vector(mu);
  printf("\n");
  printf("nu:\n");
  print_coefficient_vector(nu);
  printf("\n");
  printf("compressed nu:\n");
  print_coefficient_vector(compressed_nu);
  printf("\n");
  printf("c1 (%d):\n", c1_b_len);
  print_bytes(c1_b_len, b_c1);
  printf("\n");
  printf("c2 (%d):\n", c2_b_len);
  print_bytes(c2_b_len, b_c2);
  printf("\n");

  printf("\n\ntest, decompressed mu\n");
  coefficient_vector t_compressed_mu(p.q_, p.n_);
  byte checked_m[32];
  memset(checked_m, 0, 32);
  for (int j = 0; j < p.n_; j++) {
    t_compressed_mu.c_[j] = compress(p.q_, mu.c_[j], 1);
  }
  if (!byte_encode_from_vector(1, p.n_, t_compressed_mu.c_, checked_m)) {
    return false;
  }
  printf("recovered m from mu: ");
  print_bytes(32, checked_m);

  printf("\n\ntest, decompressed nu\n");
  coefficient_vector t_nu(p.q_, p.n_);
  if (!byte_decode_to_vector(p.dv_, p.n_, c2_b_len, b_c2, t_nu.c_)) {
    return false;
  }
  for (int j = 0; j < p.n_; j++) {
    t_nu.c_[j] = decompress(p.q_, t_nu.c_[j], p.dv_);
  }
  printf("Recovered nu\n");
  print_coefficient_vector(t_nu);
  printf("\n");
#endif
  return true;
}

// Kyber.Decrypt
//  abbreviated
//    u := Decompress(q, u, du)
//    v := Decompress(q, v, dv)
//    return (v-s^Tu, 1)
//  full
//    c1 = c[0:384duk]
//    c2 := c[384duk: 384duk+32(duk _dv)
//    u := decompress(du, byte_decode(du, c1))
//    nu := decompress(dv, byte_decode(dv, c2))
//    s^ = byte_decode(12, dek)
//    w := nu - ntt_inv(s^^T NTT(u))
//    m := byte_encode(1, compress(1,w))
//    dk is as in keygen
bool kyber_decrypt(int g, kyber_parameters& p, int dk_len, byte* dk,
      int c_len, byte* c, int* m_len, byte* m) {

  if (c_len != 32 * (p.du_ * p.k_ + p.dv_)) {
    printf("kyber_decrypt: wrong input size\n");
    return false;
  }
  byte* c1= c;
  byte* c2 = &c[32 * p.du_ * p.k_];

  byte* p_c1 = c1;
  int len = 32;
  module_vector u(p.q_, p.n_, p.k_);

  // Recover u from c1
  for (int i = 0; i < p.k_; i++) {
    if (!byte_decode_to_vector(p.du_, p.n_, len, p_c1, u.c_[i]->c_)) {
      return false;
    }
    p_c1 += len;
    for (int j = 0; j < p.n_; j++) {
      u.c_[i]->c_[j] = decompress(p.q_, u.c_[i]->c_[j], p.du_);
    }
  }

  // Recover nu from c2
  coefficient_vector compressed_nu(p.q_, p.n_);
  coefficient_vector nu(p.q_, p.n_);
  if (!byte_decode_to_vector(p.dv_, p.n_, len, c2, compressed_nu.c_)) {
    return false;
  }
  for (int j = 0; j < p.n_; j++) {
    nu.c_[j] = decompress(p.q_, compressed_nu.c_[j], p.dv_);
  }

  // Recover s_ntt from dk
  module_vector s_ntt(p.q_, p.n_, p.k_);
  for (int i = 0; i < p.k_; i++) {
    if (!byte_decode_to_vector(12, p.n_, dk_len, dk, s_ntt.c_[i]->c_)) {
      return false;
    }
  }

  module_vector u_ntt(p.q_, p.n_, p.k_);
  coefficient_vector w_ntt(p.q_, p.n_);
  coefficient_vector w(p.q_, p.n_);
  coefficient_vector compressed_w(p.q_, p.n_);

  // Transform u to ntt domain
  for (int i = 0; i < p.k_; i++) {
      if (!ntt(g, *u.c_[i], u_ntt.c_[i])) {
      printf("kyber_decrypt: ntt (1) failed\n");
      return false;
    }
  }

  // Compute w = nu - ntt_inv(s_ntt dot ntt(u))
  if (!ntt_module_vector_dot_product(s_ntt, u_ntt, &w_ntt)) {
    printf("kyber_decrypt: ntt_module_vector_dot_product failed\n");
    return false;
  }
  if (!ntt_inv(g, w_ntt, &w)) {
    printf("kyber_decrypt: ntt_inv failed\n");
    return false;
  }
  // w = -w
  for (int j = 0; j < w.len_; j++) {
    w.c_[j] = (w.q_ - w.c_[j]) % w.q_;
  }
  if (!coefficient_vector_add_to(nu, &w)) {
    printf("kyber_decrypt: coefficient_vector_add_to (3) failed\n");
    return false;
  }

  // compress and encode output message into  m
  for (int j = 0; j < p.n_; j++) {
    compressed_w.c_[j] = compress(p.q_, w.c_[j], 1);
  }
  if (!byte_encode_from_vector(1, p.n_, compressed_w.c_, m)) {
    printf("kyber_decrypt: byte_encode_from_vector (3) failed\n");
    return false;
  }
  *m_len = 32;

#if 1
  printf("\n\nDecrypt\n\n");
  printf("s_ntt:\n");
  print_module_vector(s_ntt);
  printf("u:\n");
  print_module_vector(u);
  printf("nu:\n");
  print_coefficient_vector(nu);
  printf("\n");
  printf("w:\n");
  print_coefficient_vector(w);
  printf("\n");
  printf("compressed w:\n");
  print_coefficient_vector(compressed_w);
  printf("\n");
#endif
  return true;
}

// Kem Keygen
//  abbreviated
//    z := B^32
//    (ek, dk) := kyber_keygen
//    kem_ek := ek
//    kem_dk := dk || ek || H(ek) || z
//  full
bool kyber_kem_keygen(int g, kyber_parameters& p, int* kem_ek_len, byte* kem_ek,
      int* kem_dk_len, byte* kem_dk) {
  byte z[32];
  int n_b = crypto_get_random_bytes(32, z);
  if (n_b != 32) {
    printf("kyber_kem_keygen crypto_get_random_bytes returne wrong nuber of bytes\n");
    return false;
  }
  int dk_PKE_len = 384 * p.k_;
  byte dk_PKE[dk_PKE_len];
  if (! kyber_keygen(g, p, kem_ek_len, kem_ek, &dk_PKE_len, dk_PKE)) {
    return false;
  }

  // kem_dk = dk_PKE || ek || H(ek) || z
  int len = 0;
  memcpy(&kem_dk[len], dk_PKE, dk_PKE_len);
  len += dk_PKE_len;
  memcpy(&kem_dk[len], kem_ek, *kem_ek_len);
  len += *kem_ek_len;
  sha3 h;
  if (!h.init(256, 256)) {
    return false;
  }
  h.add_to_hash(*kem_ek_len, kem_ek);
  h.finalize();
  h.get_digest(32, &kem_dk[len]);
  len += 32;
  memcpy(&kem_dk[len], z, 32);
  if (*kem_dk_len < len) {
    return false;
  }
  *kem_dk_len = len;
  return true;
}

// Kem.Encapsulate
//  m := {0,1}^256
//  (K, r) := G(H(pk), m)
//  (u,v) := Kyber.Enc(ek, m, r)
//  return K, c
bool kyber_kem_encaps(int g, kyber_parameters& p, int kem_ek_len, byte* kem_ek,
      int* k_len, byte* k, int* kem_c_len, byte* kem_c) {

  byte m[32];
  int n_b = crypto_get_random_bytes(32, m);
  if (n_b != 32) {
    printf("kyber_kem_encaps: crypto_get_random_bytes return wrong nuber of bytes\n");
    return false;
  }
  byte h_to_hash[kem_ek_len + 32];
  memcpy(h_to_hash, m, 32);
  sha3 h;
  if (!h.init(256, 256)) {
    return false;
  }
  h.add_to_hash(kem_ek_len, kem_ek);
  h.finalize();
  h.get_digest(32, &h_to_hash[32]);

  //  (K, r) := G(H(pk), m)
  byte K_r[64];
  if (!G(kem_ek_len + 32, h_to_hash, 64, K_r)) {
    return false;
  }

  int len_c = 32*(p.du_* p.k_ + p.dv_);
  if (*kem_c_len < len_c) {
    return false;
  }
  byte c[len_c];
  if (!kyber_encrypt(g, p, kem_ek_len, kem_ek,
          32, m, 32, &K_r[32], kem_c_len, kem_c)) {
    return false;
  }
  if (*kem_c_len < (len_c + 32)) {
    return false;
  }
  *kem_c_len = 32 + len_c;
  memcpy(kem_c, K_r, 32);
  memcpy(&kem_c[32], c, len_c);
  return true;
}

// Kem.Decapsulate
//  dk := dk[0:384k] = dk[0:48] (bytes)
//  ek := dk[384k:768k + 32] = dk[48:128] (bytes)
//  h := dk[768k + 32: 768k+64 = dk[128:160] (bytes)]
//  z := dk[768k+64: 768k+96 = dk[160:192] (bytes)
//  m' := Kyber.Dec(dk, c)
//  (K', r') := G(m'|| h)
//  K-bar = J(z||c, 32)
//  c' := Kyber.Enc(m',r')
//  if c != c'
//    K' := K-bar
//  else
//   error
//  return K
bool kyber_kem_decaps(int g, kyber_parameters& p, int kem_dk_len, byte* kem_dk,
      int c_len, byte* c, int* k_len, byte* k) {
  byte* dk = kem_dk;
  byte* ek = &kem_dk[48];
  byte* h = &kem_dk[128];
  byte* z = &kem_dk[160];

  int m_prime_len = 32;
  byte m_prime[m_prime_len];
  if (!kyber_decrypt(g, p, 48, dk, c_len, c, &m_prime_len, m_prime)) {
    return false;
  }
  int ek_len = 80;
  byte h_to_hash[ek_len + 32];
  memcpy(h_to_hash, m_prime, 32);
  memcpy(&h_to_hash[32], h, 32);

  //  (K_prime, r_prime) := G(H(pk), m)
  byte K_r_prime[64];
  if (!G(ek_len + 32, h_to_hash, 64, K_r_prime)) {
    return false;
  }
  byte K_bar[32];
  sha3 h_o;
  if (!h_o.init(512, 256)) {
    return false;
  }
  h_o.add_to_hash(32, z);
  h_o.add_to_hash(c_len, c);
  h_o.shake_finalize();
  h_o.get_digest(32, K_bar);

  int c_prime_len = 48 * p.k_;
  byte c_prime[c_prime_len];
  if (!kyber_encrypt(g, p, 80, ek, 32, m_prime, 32,
          &K_r_prime[32], &c_prime_len, c_prime)) {
    return false;
  }
  if (memcmp(c, c_prime, c_prime_len) == 0) {
    return false;
  }
  memcpy(k, K_bar, 32);
  *k_len = 32;
  return true;
}

