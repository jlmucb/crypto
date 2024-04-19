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
    dt_;
    eta1_ = 2;
    eta2_ = 2;
    beta_;
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

bool ntt_base_mult(int q, int g, int& in1a, int& in1b,
        int& in2a, int& in2b, int* outa, int* outb) {
  int u1 = ((in1a * in2a) % q + (((in1b * in2b) %q) * g) % q) % q;
  int u2 = (((in1a * in2b) % q) + ((in2a * in1a) %q)) % q;
  *outa = u1;
  *outb = u2;
  return true;
}

bool multiply_ntt(int g, module_vector& in1, module_vector& in2, module_vector* out) {
  for (int i = 0; i < in1.dim_; i++) {
    for (int j = 0; j < in1.n_ / 2; j += 2) {
      if (!ntt_base_mult(in1.q_, g, in1.c_[i]->c_[j], in1.c_[i]->c_[j+1],
            in2.c_[i]->c_[j], in2.c_[i]->c_[j+1],
            &(out->c_[i]->c_[j]), &(out->c_[i]->c_[j+1]))) {
        return false;
      }
    }
  }
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

bool sample_ntt(int q, int l, int b_len, byte* b, int* out_len, short int* out) {
  int i = 0;
  int j = 0;
  int loop = 0;

  if (b_len < 32) {
    return false;
  }

  while (j < l) {
    short int d1 = b[i] + 256 * (b[i+1] % 16);
    short int d2 = (b[i+1] / 16) + 16 * b[i+2];
    if (j >= *out_len)
      return false;
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
  *out_len = l;
  return true;
}

bool sample_poly_cbd(int q, int eta, int l, int b_len, byte* b,
        int* out_len, short int* out) {
  if (b_len * NBITSINBYTE < l)
    return false;

  for (int i = 0; i < l; i++) {
    short int x = 0;
    for (int j = 0; j < eta; j++)
      x += (short int) bit_in_byte_stream(2*i*eta+j, l, b);
    short int y = 0;
    for (int j = 0; j < eta; j++)
      y += (short int) bit_in_byte_stream(2*i*eta+eta+j, l, b);
    if (i >= *out_len)
      return false;
    out[i] = (q + x - y) % q;
  }
  *out_len = l;
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

bool ntt_mult(int g, coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out) {
  if (in1.len_ != in2.len_ || in1.len_ != out->len_)
    return false;
  if (in1.q_ != in2.q_ || in1.q_ != out->q_)
    return false;
  int t = 0;
  for (int i = 0; i < in1.len_; i += 2) {
    int e = (short int)(bit_reverse(i/2)>>1);
    e *= 2;
    e += 1;
    t = exp_in_ntt(in1.q_, e, g);
    if (!ntt_base_mult(in1.q_, g, in1.c_[i], in1.c_[i + 1],
            in2.c_[i], in2.c_[i + 1],
            &(out->c_[i]), &(out->c_[i + 1])))
      return false;
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
// G(s) := SHA3-512(s)
//
// PRF(eta)(s, b) := SHAKE256(s||b, 64 · eta),
// XOF(ρ, i, j) := SHAKE128(ρ||i|| j)

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
//    return (ek, dk)
bool kyber_keygen(kyber_parameters& p, int* ek_len, byte* ek,
      int* dk_len, byte* dk, module_array* A, module_vector* t,
      module_vector* e, module_vector* s) {

  if (!fill_random_module_array(A)) {
    printf("fill_random_array failed on A\n");
    return false;
  }
  if (!rand_module_coefficients(p.eta1_, *s)) {
    printf("rand_coefficients failed\n");
    return false;
  }
  if (!rand_module_coefficients(p.eta1_, *e)) {
    printf("rand_coefficients failed\n");
    return false;
  }
  module_vector r(p.q_, p.n_, p.k_);
  if (!module_apply_array(*A, *s, &r)) {
    printf("module_apply_array failed\n");
    return false;
  }
  if (!module_vector_add(r, *e, t)) {
    printf("module_vector_add failed\n");
    return false;
  }
  return true;
}

// Kyber.Encrypt
//  abbreviated
//    r := {0,1}^256
//    t := Decompress(q, t, dt)
//    (e1, e2) := beta_eta^k x beta_eta^k
//    u := Compress(q, A^T r +e1, du)
//    v := Compress(q,t^tr + e2 + closest(q/2)n, dv)
//    return c=(u,v)
//  full
//    N := 0
//    t^ := byte_decode(12, ek[0:384k])
//    rho :=  bytedecode(12, ek[384k:384k_32]
//    for (i = 0; i < k; i++) {
//      for (j=0; j < k; j++) {
//        A^[i,j] := sample_ntt(xof(rho, i, j))
//      }
//    }
//    for (i = 0; i < k; i++) {
//      r[i] = sample_poly_cdb(eta1,(PRF(eta1, r,N)))
//      n++;
//    }
//    for (i = 0; i < k; i++) {
//      e1[i] = sample_poly_cdb(eta2,(PRF(eta2, r,N)))
//      n++;
//    }
//    e1 = sample_poly_cdb(eta2,(PRF(eta2, r,N)))
//    r^ = ntt(r)
//    u = ntt_inv(A^^T(r^) + e1
//    mu = decompress(1, byte_encode(1,u))
//    nu = ntt_inv(t^^T r^) +e2 + mu
//    c1 = byte_encode(du, compress(du,u))
//    c2 = byte_encode(dv, compress(dv,nu))
//    return (c1, c2)
bool kyber_encrypt(kyber_parameters& p, int ek_len, byte* ek,
      int m_len, byte* m, module_array& A, module_vector& t,
      int r_len, byte* r, int* c_len, byte* c) {
  int l = crypto_get_random_bytes(32, r);
  module_vector e1(p.q_, p.n_, p.k_);
  module_vector e2(p.q_, p.n_, p.k_);
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
bool kyber_decrypt(kyber_parameters& p, int dk_len, byte* dk,
      int c_len, byte* c, module_vector& s, int* m_len, byte* m) {
  return true;
}

// Kem Keygen
//  abbreviated
//    z := B^32
//    (ek, dk) := kyber_keygen
//    kem_ek := ek
//    kem_dk := dk || ek || H(ek) || z
//  full
bool kyber_kem_keygen(kyber_parameters& p, int* kem_ek_len, byte* kem_ek,
      int* kem_dk_len, byte* kem_dk) {
  return true;
}

// Kem.Encapsulate
//  m := {0,1}^256
//  (K, r) := G(H(pk), m)
//  (u,v) := Kyber.Enc(ek, m, r)
//  c := (u,v)
//  K := H(K, c)
//  return c,K
bool kyber_kem_encaps(kyber_parameters& p, int kem_ek_len, byte* kem_ek,
      int* k_len, byte* k, int* c_len, byte* c) {
  return true;
}

// Kem.Decapsulate
//  dk := dk[0:384k]
//  ek := dk[384k:768k +32]
//  h := dk[768k +64: 768k+32]
//  z := dk[768k+64: 768k+96
//  m' := Kyber.Dec(dk, c)
//  (K', r') := G(m'|| h)
//  K-bar = J(z||c, 32)
//  c' := Kyber.Enc(A,t,m',r')
//  if c != c'
//    K' := K-bar
//  else
//   e
//  return K
bool kyber_kem_decaps(kyber_parameters& p, int kem_dk_len, byte* kem_dk,
      int c_len, byte* c, int* k_len, byte* k) {
  return true;
}

