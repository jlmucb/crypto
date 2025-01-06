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

// Note: (1753)^256 = -1 (mod q)
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

inline int abs(int x) {
  if (x >= 0)
    return x;
  return -x;
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

#if 0
int high_bits(int x, int a) {
  // x = x_high*a + x_low
  x = abs(x);  // check
  return x / a;
}

int low_bits(int x, int a) {
  // x = x_high*2*a + x_low
  x = abs(x); // check
  int k = x / a;
  int y = x - (k  * a);
  return y;
}
#else

void decompose(int r, int a, int q, int* r1, int* r0) {
// printf("r: %d, a: %d, q: %d\n", r, a, q);
  while (r < 0) {
    r += q;
  }
  r %= q;

  *r0 = center_normalize(r % a, a);
  if ((r - *r0) == (q - 1)) {
    *r1 = 0;
    *r0 = *r0 - 1;
  } else {
    *r1 = (r - *r0) / a;
  }
}

int high_bits(int x, int a, int q) {
  int h, l;

  decompose(x, a, q, &h, &l);
  return abs(h);
}

int low_bits(int x, int a, int q) {
  int h, l;

  decompose(x, a, q, &h, &l);
  return abs(l);
}
  
#endif

bool coefficients_high_bits(int a, coefficient_vector& in, coefficient_vector* out) {
  for (int i = 0; i < in.len_; i++) {
#if 0
    out->c_[i] = high_bits(center_normalize(in.c_[i], in.q_), a);
#else
    out->c_[i] = high_bits(in.c_[i], a, in.q_);
#endif
  }
  return true;
}

bool coefficients_low_bits(int a, coefficient_vector& in, coefficient_vector* out) {
  for (int i = 0; i < in.len_; i++) {
#if 0
    out->c_[i] = low_bits(center_normalize(in.c_[i], in.q_), a);
#else
    out->c_[i] = low_bits(in.c_[i], a, in.q_);
#endif
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
    int m = crypto_get_random_bytes(3, (::byte*)&s);
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

bool fill_module_vector_hash(module_vector& v, int size_coeff, int* sz_buf, ::byte* buf) {

  // todo: compress coefficients
  if ((v.dim_ * size_coeff * (int)sizeof(int)) > *sz_buf)
    return false;
  int sz = 0;
  for (int i = 0; i < v.dim_; i++) {
    for (int j = 0; j < size_coeff; j++) {
      memcpy(&buf[i * size_coeff + j], (::byte*)&(v.c_[i]->c_[j]), sizeof(int));
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
  int m = crypto_get_random_bytes(3, (::byte*)&s);
  s %= i;
  return s;
}

bool c_from_h(int size_in, ::byte* H, int* c) {
  ::byte s[60];

  for (int i = 0; i < 60; i++) {
      int k = i / NBITSINBYTE;
      int m = 1 << (i % NBITSINBYTE);
      s[i] = H[k] & (1<<m);
  }

  int start_index = 8;
  memset(c, 0, 256);
  for (int i = 196; i < 256; i++) {
    int j = H[start_index++] % i;
    c[i] = c[j];
    c[j] = s[255 - i] == 0 ? -1 : 1;
  }
  return true;
}

void print_cc(int len, int* cc) {
  printf("cc:\n");
  for (int kk = 0; kk < len; kk++) {
    if (cc[kk] == 0)
      printf("0");
    else if (cc[kk] == 1)
      printf("+");
    else if (cc[kk] == -1)
      printf("-");
    if ((kk%64)==63)
      printf("\n");
  }
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
            int l = crypto_get_random_bytes(3, (::byte*)&s);
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
                module_vector& s1, module_vector& s2, int m_len, ::byte* M,
                module_vector* z, int len_cc, int* cc) {

  // y: dim l_
  // tv1 = Ay, dim k
  // w1 = high_bits(tv1), dim k
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
  if (len_cc != 256) {
    printf("sign: cc wrong size %d\n", len_cc);
    return false;
  }

  bool done = false;
  int w_h_len = params.k_ * params.n_ * sizeof(int);
  ::byte w_h[w_h_len];
  memset(w_h, 0, w_h_len);
  sha3 H;

  while (!done) {
    module_vector y(params.q_, params.n_, params.l_);
    module_vector tv1(params.q_, params.n_, params.k_);
    module_vector tv2(params.q_, params.n_, params.k_);
    module_vector w1(params.q_, params.n_, params.k_);
    module_vector w3(params.q_, params.n_, params.k_);
    module_vector tu1(params.q_, params.n_, params.l_);
    module_vector tu2(params.q_, params.n_, params.k_);
    coefficient_vector c_poly(params.q_, params.n_);

    // construct y
    for (int i = 0; i < (int)params.l_; i++) {
      for (int j = 0; j < (int)params.n_; j++) {
        unsigned s = 0;
        int l = crypto_get_random_bytes(3, (::byte*)&s);
        s %= params.gamma_1_;
        y.c_[i]->c_[j] = (int) s;
      }
    }

    if (!module_apply_array(A, y, &tv1)) {
      printf("sign: module_apply_array failed\n");
      return false;
    }
#ifdef SIGNDEBUG
    printf("\ny (%d):\n", params.gamma_1_);
    print_module_vector(y);
    printf("\ntv1=Ay:\n");
    print_module_vector(tv1);
#endif

    if (!module_high_bits(2 * params.gamma_2_, tv1, &w1)) {
      printf("sign: module_high_bits failed\n");
      return false;
    }
#ifdef SIGNDEBUG
    printf("\nw1=high_bits(Ay):\n");
    print_module_vector(w1);
#endif

    // in = M || w1
    if (!H.init(512, 1024)) {
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

    int t_len = 128;
    ::byte t_c[t_len];
    memset(t_c, 0, t_len);

    if (!H.get_digest(H.num_out_bytes_, t_c)) {
      printf("sign: get digest failed\n");
      return false;
    }

    memset((::byte*)cc, 0, 256 * sizeof(int));
    if (!c_from_h(t_len, t_c, cc)) {
      return false;
    }
#ifdef SIGNDEBUG
    printf("SHAKE:\n");
    print_bytes(t_len, t_c);
    printf("\n");
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

#ifdef SIGNDEBUG
    printf("\ntu1= cs1:\n");
    print_module_vector(tu1);
    printf("\nz=y+cs1:\n");
    print_module_vector(*z);
#endif
    int inf = module_inf_norm(*z);
#ifdef SIGNDEBUG
    printf("sign: inf_norm(high_bits(z)) %d, g1-beta: %d\n",
      inf, params.gamma_1_ - params.beta_);
#endif
    if (inf >= (params.gamma_1_ - params.beta_)) {
#ifdef SIGNDEBUG
      printf("sign: compare 1(z) failed\n");
#else
      printf("sign: compare 1 failed\n");
      continue;
#endif
    }

    if (!module_vector_mult_by_scalar(c_poly, s2, &tu2)) {
      printf("sign: module_vector_mult_by_scalar failed\n");
      return false;
    }

    make_module_vector_zero(&tv2);
    make_module_vector_zero(&w3);
    if (!module_vector_subtract(tv1, tu2, &tv2)) {
      printf("sign:module_vector_mult_by_scalar failed\n");
      return false;
    }
    if (!module_low_bits(2 * params.gamma_2_, tv2, &w3)) {
      printf("sign: module_low_bits failed\n");
      return false;
    }
#ifdef SIGNDEBUG
    printf("\ntu2=cs2:\n");
    print_module_vector(tu2);
    printf("\ntv2=Ay-cs2:\n");
    print_module_vector(tv2);
    printf("\nw3=low_bits(Ay-cs2), 2 * params.gamma_2_: %d\n", 2 * params.gamma_2_);
    print_module_vector(w3);
    printf("\n");
    module_vector wa(params.q_, params.n_, params.k_);
    if (!module_low_bits(2 * params.gamma_2_, tu2, &wa)) {
      printf("sign: module_low_bits failed\n");
      return false;
    }
    printf("lowbits(cs2):\n");
    print_module_vector(wa);
    printf("\n");
    module_vector wb(params.q_, params.n_, params.k_);
    if (!module_low_bits(2 * params.gamma_2_, tv1, &wb)) {
      printf("sign: module_low_bits failed\n");
      return false;
    }
    int l1 = module_inf_norm(wa);
    printf("inf_norm(low_bits(cs2)): %d\n", l1);
    printf("\nlowbits(Ay):\n");
    print_module_vector(wb);
    printf("\n");
    int l2 = module_inf_norm(wb);
    printf("inf_norm(low_bits(Ay)): %d\n", l2);
#endif
    int low = module_inf_norm(w3);
#ifdef SIGNDEBUG
    printf("sign: inf_norm(low_bits(Ay-cs2)) %d, g2-beta: %d\n",
       low, params.gamma_2_ - params.beta_);
#endif
    if (low >= (params.gamma_2_ - params.beta_)) {
#ifdef SIGNDEBUG
      printf("compare 2 fail\n");
#else
      printf("compare 2 (low_bits(Ay-cs2) fail\n");
      continue;
#endif
    }

    done = true;
  }

  return true;
}

// w_1 := highbits(Az-ct, 2g2)
// return ||z||_inf < g1-beta and c == H(M||w1)
bool dilithium_verify(dilithium_parameters& params,  module_array& A,
        module_vector& t, int m_len, ::byte* M,
        module_vector& z, int len_cc, int* cc) {

  if (len_cc != 256) {
    printf("verify: cc len wrong %d\n", len_cc);
    return false;
  }

  // tv1 = Az, dim k
  // tu = ct, dim k
  // tv2 = tv1-tu, dim k
  // w1 = high_bits(tv2), dim k
  int w_h_len = params.k_ * params.n_ * (int)sizeof(int);
  ::byte w_h[w_h_len];
  memset(w_h, 0, w_h_len);
  int w_len = sizeof(int) * params.n_;
  ::byte added_w[w_len];
  sha3 H;

  int t_len = 128;
  ::byte t_c[t_len];
  memset(t_c, 0, t_len);

  module_vector tv1(params.q_, params.n_, params.k_);
  module_vector tv2(params.q_, params.n_, params.k_);
  module_vector tu(params.q_, params.n_, params.k_);
  module_vector w1(params.q_, params.n_, params.k_);
  module_vector w2(params.q_, params.n_, params.k_);
  coefficient_vector c_poly(params.q_, params.n_);

  if (!module_apply_array(A, z, &tv1)) {
    return false;
  }
  for (int i = 0; i < c_poly.len_; i++) {
      c_poly.c_[i] = cc[i];
  }
  if (!module_vector_mult_by_scalar(c_poly, t, &tu)) {
    return false;
  }
  if (!module_vector_subtract(tv1, tu, &tv2)) {
    return false;
  }
#ifdef VERIFYDEBUG
    printf("\ntv1= Az:\n");
    print_module_vector(tv1);
    printf("\ntu= ct:\n");
    print_module_vector(tu);
    printf("\ntv2= Az-ct:\n");
    print_module_vector(tv2);
#endif

  if (!module_high_bits(2 * params.gamma_2_, tv2, &w1)) {
    return false;
  }
#ifdef VERIFYDEBUG
    printf("\n\nw1= high_bits(Az-ct):\n");
    print_module_vector(w1);
#endif

  // in = M || w1
  if (!H.init(512, 1024)) {
    return false;
  }
  H.add_to_hash(m_len, M);
  // this is not quite right
  int tsz = w_h_len;
  if (!fill_module_vector_hash(w1, params.n_, &tsz, w_h)) {
    return false;
  }
  H.add_to_hash(tsz, w_h);
  H.shake_finalize();
  if (!H.get_digest(H.num_out_bytes_, t_c)) {
    return false;
  }

#ifdef VERIFYDEBUG
  printf("\nH(M||w1):\n");
  print_bytes(H.num_out_bytes_, t_c);
  printf("\n");
#endif

  int v_cc[256];
  memset((::byte*)v_cc, 0, 256 * sizeof(int));
  if (!c_from_h(t_len, t_c, v_cc)) {
    return false;
  }
#ifdef VERIFYDEBUG
  printf("given cc: \n");
  print_cc(256, cc);
  printf("computed cc: \n");
  print_cc(256, v_cc);
#endif

  int inf_z = module_inf_norm(z);
#ifdef VERIFYDEBUG
    printf("inf_norm(z) = %d, params.gamma_1_ - params.beta_ = %d\n", inf_z,params.gamma_1_ - params.beta_);
#endif
  if (inf_z >= (params.gamma_1_ - params.beta_)) {
    return false;
  }

  for (int i = 0; i < 256; i++) {
    if (cc[i] != v_cc[i])
      return false;
  }
  return true;
}
