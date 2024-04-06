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

// This is the "vanilla" dilithium, which is slow and has
// large keys.

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
      t_out[i + j] %= (int) in1.q_;
    }
  }

    int m = (int)in1.c_.size() - 1;
    for (int j = (2 * m); j > m; j--) {
      t_out[j -  m - 1] = reduce(t_out[j - m - 1], t_out[j], in1.q_);
    }

  for (int j = 0; j < (int)in1.c_.size(); j++) {
    if (t_out[j] >= 0)
      out->c_[j] = t_out[j];
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

bool module_vector_subtract(module_vector& in1, module_vector& in2, module_vector* out) {
  if (in1.dim_ != in2.dim_ || in1.dim_ != out->dim_)
    return false;
  module_vector neg_in2(in2.q_, in2.n_, in2.dim_);
  for (int i = 0; i < in2.dim_; i++) {
    for (int j = 0; j < in2.n_; j++) {
      neg_in2.c_[i]->c_[j] = (in2.q_ - in2.c_[i]->c_[j]) % in2.q_;
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
    printf("[%d] = ", i);
    print_coefficient_vector(*mv.c_[i]);
    printf("\n");
  }
}

int center_normalize(int x, int a) {
  int b = (a -1) /2;
  if (x >= 0) {
    if (x <= b) {
      return x;
    } 
    return (x - a);
  } else {
    if (x >= -b)
      return x;
    return (x + a);
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

bool module_high_bits(int a, module_vector& in, module_vector* out) {
  for (int i = 0; i < in.dim_; i++) {
    if (!coefficients_high_bits(a, *in.c_[i], (out->c_[i]))) {
      return false;
    }
  }
  return true;
}

bool module_low_bits(int a, module_vector& in, module_vector* out) {
  for (int i = 0; i < in.dim_; i++) {
    if (!coefficients_low_bits(a, *in.c_[i], out->c_[i])) {
      return false;
    }
  }
  return true;
}

int module_array::index(int r, int c) {
  return r * nc_ + c;
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

bool module_vector_is_zero(module_vector& in) {
  for (int i = 0; i < in.dim_; i++) {
    for (int j = 0; j < in.n_; j++) {
      if (in.c_[i]->c_[j] != 0)
        return false;
    }
  }
  return true;
}

bool make_module_vector_zero(module_vector* out) {
  for (int i = 0; i < out->dim_; i++) {
    for (int j = 0; j < out->n_; j++) {
        out->c_[i]->c_[j] = 0;
    }
  }
  return true;
}

bool module_vector_equal(module_vector& in1, module_vector& in2) {
  if (in1.dim_ != in2.dim_)
    return false;

  for (int i = 0; i < in1.dim_; i++) {
    if (!coefficient_equal(*in1.c_[i], *in2.c_[i]))
      return false;
  }

  return true;
}

bool fill_module_vector_hash(module_vector& v, int size_coeff, int* sz_buf, byte* buf) {

  // todo: compress coefficients
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
  if (!make_module_vector_zero(out)) {
    return false;
  }
  for (int i = 0; i < in2.dim_; i++) {
    if (!coefficient_mult(in1, *in2.c_[i], (out->c_[i])))
      return false;
  }
  return true;
}

int rand_int_in_range(int i) {
  // pick # between 0 and i, inclusive
  int s = 0;
  int m = crypto_get_random_bytes(3, (byte*)&s);
  s %= i;
  return s;
}

bool c_from_h(int size_in, byte* H, int* c) {
  byte s[60];

  for (int i = 0; i < 60; i++) {
      int k = i / NBITSINBYTE;
      int m = 1 << (i % NBITSINBYTE);
      s[i] = H[k] & (1<<m);
  }

  memset(c, 0, 256);
  for (int i = 196; i < 256; i++) {
    int j = rand_int_in_range(i);
    c[i] = c[j];
    c[j] = s[255 - i] == 0 ? -1 : 1;
  }
  return true;
}


// A is R_q[k*l]
// t is module coefficient vector of length k
// s1 is module coefficient vector of length l
// s2 is module coefficient vector of length k
bool dilithium_keygen(dilithium_parameters& params, module_array* A,
  module_vector* t, module_vector* s1, module_vector* s2) {
  // A := R_q^kxl
  // s1: dim l, s2: dim k
  // tv = As1 (dim k)
  // t := tv + s2 (dim k)
  if (t->dim_ != params.k_ || s1->dim_ != params.l_ || s2->dim_ != params.k_) {
    printf("keygen dims wrong, t: %d,  s1: %d, s2: %d, k: %d, l: %d\n",
        t->dim_, s1->dim_, s2->dim_, params.k_, params.l_);
    return false;
  }

  module_vector tv(params.q_, params.n_, params.k_);
  for (int r = 0; r < params.k_; r++) {
    for (int c = 0; c < params.l_; c++) {
      for (int k = 0; k < params.n_; k++) {
            int s = 0;
            int l = crypto_get_random_bytes(3, (byte*)&s);
            s %= params.q_;
            A->c_[A->index(r, c)]->c_[k] = s;
      }
    }
  }

  // (s_1, s_2) := S_eta^l x S_eta^k
  for (int ll = 0; ll < s1->dim_; ll++) {
      if (!rand_coefficient(params.eta_, *(s1->c_[ll]))) {
        printf("rand_coefficient failed on s1\n");
        return false;
      }
  }

  for (int ll = 0; ll < s2->dim_; ll++) {
      if (!rand_coefficient(params.eta_, *(s2->c_[ll]))) {
        printf("rand_coefficient failed on s2\n");
        return false;
      }
  }

  if (!module_apply_array(*A, *s1, &tv)) {
        printf("module_apply_array failed\n");
    return false;
  }
  // t := As_1 + s_2
  if (!module_vector_add(tv, *s2, t)) {
    return false;
  }
  return true;
}

// z := no
// while z == no {
//    y := S_g1^l - 1
//    w_1 := highbits(Ay, 2g2)
//    c := H(M||w_1)
//    z := y + cs_1
//    if (||z||_inf > g1-beta or lowbits(Ay-cs2, 2g_1)>= g1-beta then z := no
// }
bool dilithium_sign(dilithium_parameters& params,  module_array& A,  module_vector& t,
                module_vector& s1, module_vector& s2, int m_len, byte* M,
                module_vector* z, int len_c, byte* c) {

  // y: dim l_
  // tv1 = Ay, dim k
  // w1 = high_bits(w1), dim k
  // tu1 = c*s1, dim l
  // z = y + c tu1, dim l
  // tu2 = c*s2, dim k
  // tv2 = tv1 - tu2, dim k
  // w2 = low_bits(tv2), dim k
  if (t.dim_ != params.k_ || s1.dim_ != params.l_ || s2.dim_ != params.k_ || z->dim_ != params.l_) {
    printf("sign: wrong dimensions, t: %d, s1: %d, s2: %d, z: %d\n",
      t.dim_, s1.dim_, s2.dim_, z->dim_);
    return false;
  }

  bool done = false;
  memset(c, 0, len_c);
  int w_h_len = params.k_ * params.n_ * sizeof(int);
  byte w_h[w_h_len];
  memset(w_h, 0, w_h_len);
  sha3 H;

  while (!done) {
    module_vector y(params.q_, params.n_, params.l_);
    module_vector tv1(params.q_, params.n_, params.k_);
    module_vector tv2(params.q_, params.n_, params.k_);
    module_vector w1(params.q_, params.n_, params.k_);
    module_vector w2(params.q_, params.n_, params.k_);
    module_vector tu1(params.q_, params.n_, params.l_);
    module_vector tu2(params.q_, params.n_, params.k_);
    coefficient_vector c_poly(params.q_, params.n_);

    int t_len = 32;
    memset(c, 0, t_len);

    // construct y
    for (int i = 0; i < (int)params.l_; i++) {
      for (int j = 0; j < (int)params.n_; j++) {
        unsigned s;
        int l = crypto_get_random_bytes(3, (byte*)&s);
        s %= params.gamma_1_;
        y.c_[i]->c_[j] = (int) s;
      }
    }

    if (!module_apply_array(A, y, &tv1)) {
      printf("sign: module_apply_array failed\n");
      return false;
    }
#if 1
    printf("tv1:\n");
    print_module_vector(tv1);
#endif

    if (!module_high_bits(2 * params.gamma_2_, tv1, &w1)) {
      printf("sign: module_high_bits failed\n");
      return false;
    }
#if 1
    printf("w1:\n");
    print_module_vector(w1);
#endif

    // in = M || w1
    if (!H.init(512, 256)) {
      printf("sign: hash init failed\n");
      return false;
    }
    H.add_to_hash(m_len, M);

    int tsz = w_h_len;
    if (!fill_module_vector_hash(w1, params.n_, &tsz, w_h)) {
      printf("sign: fill_module_vector_hash failed\n");
      return false;
    }

    H.add_to_hash(tsz, w_h);
    H.shake_finalize();
    if (!H.get_digest(H.num_out_bytes_, c)) {
      printf("sign: get digest failed\n");
      return false;
    }

    int cc[256];
    memset((byte*)cc, 0, 256 * sizeof(int));
    if (!c_from_h(32, c, cc)) {
      printf("sign: c_from_h\n");
      return false;
    }
#if 1
    printf("cc:\n");
    for (int kk = 0; kk < 256; kk++) {
      if (cc[kk] == 0)
        printf("0");
      else if (cc[kk] == 1)
        printf("+");
      else if (cc[kk] == -1)
        printf("-");
      if ((kk%64)==63)
        printf("\n");
    }
#endif
    for (int i = 0; i < c_poly.len_; i++) {
        c_poly.c_[i] = cc[i];
    }
    if (!module_vector_mult_by_scalar(c_poly, s1, &tu1)) {
      printf("sign: module_vector_mult_by_scalar failed\n");
      return false;
    }

    if (!module_vector_add(y, tu1, z)) {
      printf("sign: module_vector_add failed\n");
      return false;
    }

#if 1
    printf("\ntu1:\n");
    print_module_vector(tu1);
    printf("\n");
    printf("tv1:\n");
    print_module_vector(tv1);
    printf("\n");
#endif

    int inf = module_inf_norm(*z);
#if 1
    printf("sign: inf_norm(high_bits(z)) %d, g1-beta: %d\n",
      inf, params.gamma_1_ - params.beta_);
#endif
    if (inf >= (params.gamma_1_ - params.beta_)) {
#if 1
      printf("sign: compare 1 failed\n");
#else
      continue;
#endif
    }

    if (!module_vector_mult_by_scalar(c_poly, s2, &tu2)) {
      printf("sign: module_vector_mult_by_scalar failed\n");
      return false;
    }

    if (!module_vector_subtract(tv1, tu2, &tv2)) {
      printf("sign:module_vector_mult_by_scalar failed\n");
      return false;
    }

    if (!module_low_bits(2 * params.gamma_2_, tv2, &w2)) {
      printf("sign: module_low_bits failed\n");
      return false;
    }
#if 1
    printf("w2, 2 * params.gamma_2_: %d\n", 2 * params.gamma_2_);
    print_module_vector(w2);
    printf("\n");
#endif
    int low = module_inf_norm(w2);
#if 1
    printf("sign: inf_norm(low_bits(tv2)) %d, g2-beta: %d\n",
       low, params.gamma_2_ - params.beta_);
#endif
    if (low >= (params.gamma_2_ - params.beta_)) {
#if 0
      continue;
#endif
    }

    done = true;
  }

  return true;
}

// w_1' := highbits(Az-ct, 2g2)
// return ||z||_inf < g1-beta and c == H(M||w1)
bool dilithium_verify(dilithium_parameters& params,  module_array& A,
        module_vector& t, int m_len, byte* M,
        module_vector& z, int len_c, byte* c) {


  // tv1 = Az, dim k
  // tu = ct, dim k
  // tv2 = tv1-tu, dim k
  // w1 = high_bits(tv2), dim k
  int w_h_len = params.k_ * params.n_ * (int)sizeof(int);
  byte w_h[w_h_len];
  memset(w_h, 0, w_h_len);
  int w_len = sizeof(int) * params.n_;
  byte added_w[w_len];
  sha3 H;

  if (!H.init(512, 256)) {
    return false;
  }

  // in = M || w1
  int t_len = 32;
  byte tc[t_len];
  memset(tc, 0, t_len);

  module_vector tv1(params.q_, params.n_, params.k_);
  module_vector tv2(params.q_, params.n_, params.k_);
  module_vector tu(params.q_, params.n_, params.k_);
  module_vector w1(params.q_, params.n_, params.k_);
  coefficient_vector c_poly(params.q_, params.n_);
  int cc[256];

  H.add_to_hash(m_len, M);
  // this is not quite right
  int tsz = w_h_len;
  if (!fill_module_vector_hash(w1, params.n_, &tsz, w_h)) {
    return false;
  }
  H.add_to_hash(tsz, w_h);
  H.shake_finalize();
  if (!H.get_digest(H.num_out_bytes_, tc)) {
    return false;
  }

  if (!module_apply_array(A, z, &tv1)) {
    return false;
  }

  if (!c_from_h(32, c, cc))
    return false;
  for (int i = 0; i < c_poly.len_; i++) {
      c_poly.c_[i] = cc[i];
  }
  if (!module_vector_mult_by_scalar(c_poly, t, &tu)) {
    return false;
  }

  // actually subtract
  if (!module_vector_subtract(tv1, tu, &tv2)) {
    return false;
  }

  if (!module_high_bits(2 * params.gamma_2_, tv2, &w1)) {
    return false;
  }

  if (module_inf_norm(z) >= (params.gamma_1_ - params.beta_))
    return false;

  return memcmp(c, tc, t_len) == 0;
}

