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
// File: dilithium.cc

#include "crypto_support.h"
#include "dilithium.h"
#include "sha3.h"

using namespace std;

coefficient_vector::coefficient_vector(int q, int dim) {
  q_ = q;
  len_ = dim;

  c_.resize(dim, 0);
  for (int i = 0; i < dim; i++)
    c_[i] = 0;
}

coefficient_vector::~coefficient_vector() {
}

dilithium_parameters::dilithium_parameters() {
  n_ = 0;
  k_ = 0;
  l_ = 0;
  q_ = 0;
  gamma_1_ = 0;
  gamma_2_ = 0;
  d_ = 0;
  eta_ = 0;
  beta_= 0;
}

dilithium_parameters::~dilithium_parameters() {
  n_ = 0;
  k_ = 0;
  l_ = 0;
  q_ = 0;
  gamma_1_ = 0;
  gamma_2_ = 0;
  d_ = 0;
  eta_ = 0;
  beta_= 0;
}

void print_coefficient_vector(coefficient_vector& v) {
  if (v.c_.size() == 0)
    return;
  printf("(%d[%d] + ", v.c_[v.c_.size()-1], (int)v.c_.size()-1);
  for (int i = (int)v.c_.size() - 2; i>0; i--) {
    printf("%d[%d] + ", v.c_[i], i);
    if ((i%8) ==0)
      printf("\n  ");
  }
  printf("%d[%d])\n", v.c_[0], 0);
}

void print_dilithium_parameters(dilithium_parameters& p) {
  vector<int> g1(10, 0);
  printf("Dilithium parameters, ");
  printf("q: %d, n: %d, k: %d, l: %d, d: %d, gamma 1: %d, gamma 2: %d, eta: %d, beta: %d\n",
      p.q_, p.n_, p.k_, p.l_, p.d_, p.gamma_1_, p.gamma_2_, p.eta_, p.beta_);
}

bool init_dilithium_parameters(dilithium_parameters* p) {
  p->q_ = (1<<23) - (1<<13) + 1;
  p->n_ = 256;
  p->k_ = 5;
  p->l_ = 4;
  p->d_ = 14;
  p->wt_c_ = 60;
  p->gamma_1_ = (p->q_ - 1) / 16;
  p->gamma_2_ = p->gamma_1_ / 2;
  p->eta_ = 5;
  p->beta_ = 275;
  return true;
}

bool vector_add(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out) {
  if (in1.c_.size() != in2.c_.size() || out->c_.size() < in1.c_.size())
    return false;
  for (int i = 0; i < (int)in1.c_.size(); i++)
      out->c_[i] = (in1.c_[i] + in2.c_[i]) % in1.q_;
  return true;
}

int reduce(int a, int b, int q) {
  return (q + a - b) % q;
}

bool vector_mult(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out) {
  // multiply and reduce by (x**in1.c_.size() + 1)
  if (in1.c_.size() != in2.c_.size())
    return false;

  vector<int> t_out;
  t_out.resize(2 * in1.c_.size() - 1);
  for (int i = 0; i < (int)t_out.size(); i++)
    t_out[i] = 0;

  for (int i = 0; i < (int)in1.c_.size(); i++) {
    for (int j = 0; j < (int)in2.c_.size(); j++) {
      t_out[i + j] = (t_out[i + j] + (in1.c_[i] * in2.c_[j])) % in1.q_;
    }
#if 0
    printf("t_out (%d): ", i);
    for (int k = t_out.size() - 1; k >= 0; k--)
      printf("%d ", t_out[k]);
  printf("\n");
#endif
  }

#if 0
  printf("t_out: ");
  for (int k = t_out.size() - 1; k >= 0; k--)
    printf("%d ", t_out[k]);
  printf("\n");
#endif

  int m = (int)in1.c_.size() - 1;
  for (int j = (2 * m); j > m; j--) {
    t_out[j -  m] = reduce(t_out[j - m], t_out[j], in1.q_);
  }

  for (int j = 0; j <= m; j++)
    out->c_[j] = t_out[j];

  return true;
}

module_vector::module_vector(int q, int n, int dim) {
  q_ = q;
  n_ = n;
  dim_ = dim;
  c_ = new coefficient_vector*[dim];
}

module_vector::~module_vector() {
  // delete all the coefficient vectors
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
      if (!vector_add(*in1.c_[i], *in2.c_[i], out->c_[i]))
        return false;
  }
  return true;
}

bool module_apply_array(module_array& A, module_vector& v, module_vector* out) {
  return false;
}

void print_module_array(module_array& ma) {
  for (int r = 0; r < ma.nr_; r++) {
    for (int c = 0; c < ma.nc_; c++) {
      printf("A[%d, %d] = ", r + 1, c + 1);
      print_coefficient_vector(*ma.c_[ma.index(r, c)]);
      printf("\n");
    }
  }
  printf("\n");
}

void print_module_vector(module_vector& mv) {
  for (int i = 0; i < (int)mv.dim_; i++) {
    print_coefficient_vector(*mv.c_[i]);
    printf("[%d] = ", i);
    printf("\n");
  }
}

int inf_norm(vector<int> v) {
  int x = v[0];
  for (int i = 1; i < (int)v.size(); i++) {
    if (v[i] > x)
        x = v[i];
  }
  return x;
}

int high_bits(int x, int a) {
  // x = x_high*2*a + x_low
  return x / (2 * a);
}

int low_bits(int x, int a) {
  // x = x_high*2*a + x_low
  int k = x / (2 * a);
  return x - k * 2 * a;  //shift?
}

bool coefficients_high_bits(int a, coefficient_vector& in, coefficient_vector* out) {
  for (int i = 0; i < in.len_; i++) {
    out->c_[i] = high_bits(in.c_[i], a);
  }
  return true;
}

bool coefficients_low_bits(int a, coefficient_vector& in, coefficient_vector* out) {
  for (int i = 0; i < in.len_; i++) {
    out->c_[i] = low_bits(in.c_[i], a);
  }
  return true;
}

int module_array::index(int r, int c) {
  return r * nc_ + c;
}

bool rand_coefficient(int top, coefficient_vector& v) {
  for (int k = 0; k < (int)v.c_.size(); k++) {
    int s = 0;
    int m = crypto_get_random_bytes(4, (byte*)&s);
    s %= top;
    v.c_[k] = s;
  }
  return true;
}

bool fill_module_vector_hash(module_vector& v, int size_coeff, int* sz_buf, byte* buf) {

  if ((v.dim_ * size_coeff * (int)sizeof(int)) > *sz_buf)
    return false;
  int sz = 0;
  for (int i = 0; i < v.dim_; i++) {
    for (int j = 0; j < size_coeff; j++) {
      memcpy(&buf[i * size_coeff + j], (byte*)&(v.c_[i]->c_[j]), sizeof(int));
      sz += (int)sizeof(int);
    }
  }
  *sz_buf = sz;
  return true;
}

bool module_vector_mult_by_scalar(coefficient_vector& in1, module_vector& in2, module_vector* out) {

  for (int i = 0; i < in2.dim_; i++) {
    if (!vector_mult(in1, *in2.c_[i], (out->c_[i])))
      return false;
  }
  return true;
}


// A is R_q[k*l]
// t is module coefficient vector of length l
// s1 is module coefficient vector of length l
// s2 is module coefficient vector of length k
bool dilithium_keygen(dilithium_parameters& params, module_array* A, module_vector* t,
                module_vector* s1, module_vector* s2) {

  // A := R_q^kxl
  for (int r = 0; r < params.k_; r++) {
    for (int c = 0; c < params.l_; r++) {
      for (int k = 0; k < params.n_; k++) {
            int s = 0;
            int l = crypto_get_random_bytes(4, (byte*)&s);
            s %= params.q_;
            A->c_[A->index(r, c)]->c_[k] = s;
      }
    }
  }

  // (s_1, s_2) := S_eta^k x S_eta^l
  for (int ll = 0; ll < s1->dim_; ll++) {
      if (!rand_coefficient(params.eta_, *(s1->c_[ll]))) {
        return false;
      }
  }

  for (int ll = 0; ll < s1->dim_; ll++) {
      if (!rand_coefficient(params.eta_, *(s2->c_[ll]))) {
        return false;
      }
  }

  module_vector tv(params.q_, params.n_, params.l_);
  if (!module_apply_array(*A, *s1, &tv)) {
    return false;
  }
  // t := As_1 + s_2
  if (module_vector_add(tv, *s2, t)) {
    return false;
  }
  return true;
}

bool dilithium_sign(dilithium_parameters& params,  module_array& A,  module_vector& t,
                module_vector& s1, module_vector& s2, int m_len, byte* M,
                module_vector* z, int len_c, byte* c) {

  return true;

  // z := no
  // while z == no {
  //    y := S_g1^l - 1
  //    w_1 := highbits(Ay, 2g2)
  //    c := H(M||w_1)
  //    z := y + cs_1
  //    if (||z||_inf > g1-beta or lowbits(Ay-cs2, 2g_1)>= g1-beta then z := no
  // }
  bool done = false;

#if 1
  int w_h_len = params.k_ * params.n_ * sizeof(int);
  byte w_h[w_h_len];
  memset(w_h, 0, w_h_len);
  sha3 H;

  while (!done) {
    module_vector y(params.q_, params.n_, params.k_);
    module_vector tv(params.q_, params.n_, params.l_);
    if (!module_apply_array(A, y, &tv)) {
      return false;
    }
    coefficient_vector w1(params.q_, params.k_);

    // fix
    /*
    if (!coefficients_high_bits(2 * params.gamma_1_, tv, &w1)) {
      return false;
    }
     */

    int t_len = 32;
    byte tc[t_len];
    memset(tc,0, t_len);

    // in = M || w1
    H.add_to_hash(m_len, M);

    // this is not quite right
    int tsz = w_h_len;
    /*
    if (!fill_module_vector_hash(w1, params.n_, &tsz, w_h)) {
      return false;
    }
    */
    H.add_to_hash(tsz, w_h);
    H.shake_finalize();
    if (!H.get_digest(H.num_out_bytes_, tc)) {
      return false;
    }

    coefficient_vector c_poly(params.q_, params.n_);
    module_vector tu(s1.q_, params.n_, s1.dim_);
    for (int i = 0; i < c_poly.len_; i++) {
        c_poly.c_[i] = (int)(w_h[(i / NBITSINBYTE)] & (1 << (i % 8)));
    }
    if (!module_vector_mult_by_scalar(c_poly, s1, &tu)) {
      return false;
    }

    if (!module_vector_add(y, tu, z)) {
      return false;
    }

    /*
    int inf = inf_norm(*z);
    if (inf > (params.gamma_1_ - params.beta_)) {
      return false;
    }
     */
    module_vector tv2(params.q_, params.n_, params.k_);
    if (!module_vector_add(tv, s2, &tv2)) {
      return false;
    }
    // Fix
    coefficient_vector w2(params.q_, params.k_);
    if (!coefficients_low_bits(2 * params.gamma_1_, w2, &w2)) {
      continue;
    }
    int low = inf_norm(w2.c_);
    if (low > (params.gamma_1_ - params.beta_)) {
      continue;
    }

    done = true;
  }
#endif

  return true;
}

bool dilithium_verify(dilithium_parameters& params,  module_array& A, module_vector& t,
                module_vector& s1, module_vector& s2, int m_len, byte* M,
                module_vector& z, int len_c, byte* c) {

  // w_1' := highbits(Az-ct, 2g2)
  // return ||z||_inf < g1-beta and c == H(M||w1)
  return true;

#if 0
  int w_h_len = params.k_ * params.n_ * sizeof(int);
  byte w_h[w_h_len];
  memset(w_h, 0, w_h_len);
  int w_len = sizeof(int) * params.n_;
  byte added_w[w_len];
  sha3 H;

  if (!H.init(512, 256)) {
    return false;
  }

  module_vector tv1(params.q_, params.n_, params.k_);
  module_vector tv2(params.q_, params.n_, params.k_);
  if (!module_apply_array(A, z, &tv1)) {
    return false;
  }
  if (!module_add(tv1, *, &tv2)) {
    return false;
  }
  coefficient_vector w1(params.q_, params.k_);
  if (!coefficients_high_bits(2 * params.gamma2_, tv, &w1)) {
    return false;
  }

  // in = M || w1
  int t_len = 32;
  byte tc[t_len];
  memset(tc,0, t_len);
  H.add_to_hash(m_len, M);

  // this is not quite right
  int tsz = w_h_len;
  /*
  if (!fill_module_vector_hash(w1, params.n_, &tsz, w_h)) {
    return false;
  }
  */
  H.add_to_hash(tsz, w_h);
  H.shake_finalize();
  if (!H.get_digest(H.num_out_bytes_, tc)) {
    return false;
  }

  return memcmp(c, tc, t_len) == 0;
#endif
}

