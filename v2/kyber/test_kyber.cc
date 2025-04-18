// Copyright 2014-2024 John Manferdelli, All Rights Reserved.
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
// File: test_kyber.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "kyber.h"

DEFINE_bool(print_all, false, "Print intermediate test computations");


bool test_kyber1() {
  kyber_parameters p;

  if (!p.init_kyber(256)) {
    printf("Could not init kyber parameters\n");
  }
  print_kyber_parameters(p);
  int g = 17;

  int ek_len = 384 * p.k_ + 32;
  byte_t ek[ek_len];
  memset(ek, 0, ek_len);
  int dk_len = 384 * p.k_ + 96;
  byte_t dk[dk_len];
  memset(dk, 0, dk_len);

  module_array A(p.q_, p.n_, p.k_, p.k_);
  module_vector e(p.q_, p.n_, p.k_);
  module_vector s(p.q_, p.n_, p.k_);
  module_vector t(p.q_, p.n_, p.k_);
  
  if (!kyber_keygen(g, p, &ek_len, ek, &dk_len, dk)) {
    printf("Could not init kyber_keygen\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("ek (%d): \n",ek_len);
    print_bytes(ek_len, ek);
    printf("\n");
    printf("dk (%d):\n", dk_len);
    print_bytes(dk_len, dk);
    printf("\n");
  }

  int m_len = 32;
  byte_t m[m_len];
  int r_len = 32;
  byte_t r[r_len];
  int c_len = 32 * (p.du_ * p.k_ + p.dv_);
  byte_t c[c_len];
  memset(m, 0, m_len);
  memset(c, 0, c_len);
  memset(r, 0, r_len);
  int b_r_len = 32;
  byte_t b_r[b_r_len];
  memset(b_r, 0, b_r_len);
  int n_b = crypto_get_random_bytes(b_r_len, b_r);
  if (n_b != b_r_len) {
    printf("wrong return from crypto_get_random_bytes\n");
    return false;
  }
  m[1] = 0xff;
  m[3] = 0x0f;
  m[5] = 0x10;
  m[7] = 0x11;

  if (!kyber_encrypt(g, p, ek_len, ek, m_len, m,
          b_r_len, b_r, &c_len, c)) {
    printf("Could not init kyber_encrypt\n");
    return false;
  }
  int recovered_m_len = 32;
  byte_t recovered_m[m_len];
  memset(recovered_m, 0, recovered_m_len);
  if (!kyber_decrypt(g, p, dk_len, dk, c_len, c, &recovered_m_len, recovered_m)) {
    printf("Could not init kyber_decrypt\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("recovered m: ");
    print_bytes(recovered_m_len, recovered_m);
    printf("\n\nkyber complete\n\n");
  }
  if (memcmp(m, recovered_m, m_len) != 0) {
    printf("message and recovered message dont match\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("\n\nkem\n\n");
  }

  int kem_ek_len = 384 * p.k_ + 32;
  byte_t kem_ek[kem_ek_len];
  memset(kem_ek, 0, kem_ek_len);
  int kem_dk_len = 768 * p.k_ + 96;

  byte_t kem_dk[kem_dk_len];
  memset(kem_dk, 0, kem_dk_len);
  if (!kyber_kem_keygen(g, p, &kem_ek_len, kem_ek, &kem_dk_len, kem_dk)) {
    printf("Could not init kem_keygen\n");
    return false;
  }

  int kem_c_len = 32 * (p.du_ * p.k_ + p.dv_);
  byte_t kem_c[kem_dk_len];
  memset(kem_c, 0, kem_c_len);

  int kem_k_len = 32;
  byte_t kem_k[kem_k_len];
  memset(kem_k, 0, kem_k_len);

  if (FLAGS_print_all) {
     printf("\n\nkem_keygen\n\n");
     printf("kem_ek (%d):\n", kem_ek_len);
     print_bytes(kem_ek_len, kem_ek);
     printf("\n");
     printf("kem_dk (%d):\n", kem_dk_len);
     print_bytes(kem_dk_len, kem_dk);
     printf("\n");
  }

  if (!kyber_kem_encaps(g, p, kem_ek_len, kem_ek, &kem_k_len,
                          kem_k, &kem_c_len, kem_c)) {
    printf("Could not init kem_encaps\n");
    return false;
  }

  if (FLAGS_print_all) {
     printf("\n\nkem_encaps\n\n");
     printf("k (%d): ", kem_k_len);
     print_bytes(kem_k_len, kem_k);
     printf("\n");
     printf("c (%d):\n", kem_c_len);
     print_bytes(kem_c_len, kem_c);
     printf("\n");
  }

  int recovered_k_len = 32;
  byte_t recovered_k[recovered_k_len];
  memset(recovered_k, 0, recovered_k_len);

  if (!kyber_kem_decaps(g, p, kem_dk_len, kem_dk, kem_c_len, kem_c,
                           &recovered_k_len, recovered_k)) {
    printf("Could not init kem_decaps\n");
    return false;
  }

  if (FLAGS_print_all) {
     printf("\n\nkem_decaps\n\n");
     printf("key           (%d): ", kem_k_len);
     print_bytes(kem_k_len, kem_k);
     printf("recovered key (%d): ", recovered_k_len);
     print_bytes(recovered_k_len, recovered_k);
  }

  if (memcmp(kem_k, recovered_k, recovered_k_len) != 0) {
    printf("Generated and encapsulated keys don't match\n");
    return false;
  }

  return true;
}

bool test_kyber_support() {
  int a, b, c, r;

  a = 1;
  b = 2;
  r = round(a,b);
  if (FLAGS_print_all) {
    printf("a: %d, b: %d. round(a/b): %d\n", a, b, r);
  }
  if (r != 1) {
    printf("round fail(1)\n");
    return false;
  }

  a = 5;
  b = 4;
  r = round(a,b);
  if (FLAGS_print_all) {
    printf("a: %d, b: %d. round(a/b): %d\n", a, b, r);
  }
  if (r != 1) {
    printf("round fail(2)\n");
    return false;
  }

  a = 1;
  b = 4;
  r = round(a,b);
  if (FLAGS_print_all) {
    printf("a: %d, b: %d. round(a/b): %d\n", a, b, r);
  }
  if (r != 0) {
    printf("round fail(3)\n");
    return false;
  }

  int q, x, d;
  q = 3329;
  x =  5;
  d = 11;
  r = compress(q, x, d);
  if (FLAGS_print_all) {
    printf("q: %d, x: %d, d: %d. compress: %d\n", q, x, d, r);
  }
  if (r != 3) {
    printf("compress fail(1)\n");
    return false;
  }

  x = r;
  r = decompress(q, x, d);
  if (FLAGS_print_all) {
    printf("q: %d, x: %d, d: %d. decompress: %d\n", q, x, d, r);
  }
  if (r != 5) {
    printf("decompress fail(1)\n");
    return false;
  }

  byte_t b1, b2;
  b1 = 0xc;
  b2 = bit_reverse(b1);
  if (FLAGS_print_all) {
    printf("%02x reversed is %02x\n", b1, b2);
  }
  if (b2 != 0x30) {
    printf("bit_reverse fail(1)\n");
    return false;
  }
  const char* str = "abc";
  int g_out_len = 32; 
  byte_t g_out[g_out_len];
  memset(g_out, 0, g_out_len);
  if (!G(strlen(str), (byte_t*) str, NBITSINBYTE * g_out_len, g_out)) {
    printf("G failed\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("\nG for %s is: ", str);
    print_bytes(g_out_len, g_out);
  }

  memset(g_out, 0, g_out_len);
  if (!prf(5, strlen(str), (byte_t*)str, strlen(str), (byte_t*)str, g_out_len * NBITSINBYTE, g_out)) {
    printf("prf failed\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("prf for %s is: ", str);
    print_bytes(g_out_len, g_out);
  }

  memset(g_out, 0, g_out_len);
  int i1 = 1;
  int i2 = 2;
  if (!xof(strlen(str), (byte_t*) str, i1, i2, NBITSINBYTE * g_out_len, g_out)) {
    printf("xof failed\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("xof for %s is: ", str);
    print_bytes(g_out_len, g_out);
  }
  printf("\n");

  int int_in[4] = {
    0x000aaa, 0x000555, 0x000eee, 0x000111
  };
  int dd = 12;
  int b_out_len = 6;
  byte_t b_out[b_out_len];
  memset(b_out, 0, 6);

  if (FLAGS_print_all) {
    printf("int string, %d bits per int: %08x %08x %08x %08x\n",
      dd, int_in[0], int_in[1], int_in[2], int_in[3]);
  }
  for (int i = 0; i < 48; i++) {
    byte_t b = bit_from_ints(dd, i, int_in);
    if (FLAGS_print_all) {
      printf("(%d, %d) ", i, (int)b);
    }
  }
  if (FLAGS_print_all) {
    printf("\n");
  }
  if (!byte_encode(dd, 4, int_in, b_out)) {
    printf("byte_encode failed\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("As bytes: ");
    print_bytes(6, b_out);
  }

  int recovered_int[4];
  if (!byte_decode(dd, 4, b_out_len, b_out, recovered_int)) {
    printf("byte_decode failed\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("As ints again: ");
    for (int i = 0; i < 4; i++)
      printf("%08x ", recovered_int[i]);
    printf("\n\n");
  }
  for (int i = 0; i < 4; i++) {
    if (int_in[i] != recovered_int[i]) {
      printf("decode after encode is not identical\n");
      return false;
    }
  }

  int e = 4;
  int base = 2;

  int ex = exp_in_ntt((short int)q, e, base);
  if (FLAGS_print_all) {
    printf("%d^%d (mod %d) = %d\n", base, e, q, ex);
  }
  if (ex != 16) {
    printf("exp fail (1)\n");
    return false;
  }

  e = 12;
  ex = exp_in_ntt(q, e, base);
  if (FLAGS_print_all) {
    printf("%d^%d (mod %d) = %d\n", base, e, q, ex);
  }
  if (ex != 767) {
    printf("exp fail (2)\n");
    return false;
  }

  e = 1;
  base = 17;
  ex = exp_in_ntt((short int)q, e, base);
  if (FLAGS_print_all) {
    printf("%d^%d (mod %d) = %d\n", base, e, q, ex);
  }
  if (ex != 17) {
    printf("exp fail (3)\n");
    return false;
  }

  e = 3;
  base = 17;
  ex = exp_in_ntt((short int)q, e, base);
  if (FLAGS_print_all) {
    printf("%d^%d (mod %d) = %d\n", base, e, q, ex);
  }
  if (ex != 1584) {
    printf("exp fail (4)\n");
    return false;
  }

  e = 4;
  base = 17;
  ex = exp_in_ntt((short int)q, e, base);
  if (FLAGS_print_all) {
    printf("%d^%d (mod %d) = %d\n", base, e, q, ex);
  }
  if (ex != 296) {
    printf("exp fail (5)\n");
    return false;
  }

  e = 128;
  base = 17;
  ex = exp_in_ntt((short int)q, e, base);
  if (FLAGS_print_all) {
    printf("%d^%d (mod %d) = %d\n", base, e, q, ex);
  }
  if (ex != 3328) {
    printf("exp fail (6)\n");
    return false;
  }

  int bb_len = 16;
  byte_t bb[16] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  };
  printf("\nbit_in_byte_stream: \n");
  for (int i = 0; i < bb_len * NBITSINBYTE; i++) {
    byte_t h = bit_in_byte_stream(i, bb_len, bb);
    printf("%d", h);
    if ((i%32) == 31)
      printf("\n");
  }
  printf("\n\n");

  kyber_parameters p;
  if (!p.init_kyber(256)) {
    printf("Could not init kyber parameters\n");
  }
  print_kyber_parameters(p);

  int g = 17;
  int i1a = 2;
  int i2a = 5;
  int i1b = 1;
  int i2b = 3;
  int oa = 0;
  int ob = 0;
  if (!ntt_base_mult(p.q_, g, i1a, i1b, i2a, i2b, &oa, &ob)) {
    printf("Could not ntt_base_mult\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("ntt_base_mult (%d, %d) (%d, %d) = (%d, %d)\n", i1a, i1b, i2a, i2b, oa, ob);
  }

  coefficient_vector in1(p.q_, p.n_);
  coefficient_vector in2(p.q_, p.n_);
  coefficient_vector out(p.q_, p.n_);

  if (!coefficient_vector_zero(&in1)) {
    printf("Cant zero in1\n");
    return false;
  }
  if (!coefficient_vector_zero(&in2)) {
    printf("Cant zero in2\n");
    return false;
  }
  if (!coefficient_vector_zero(&out)) {
    printf("Cant zero out\n");
    return false;
  }

  int sample_ntt_b_len = 384;
  byte_t sample_ntt_b[sample_ntt_b_len];
  memset(sample_ntt_b, 0, sample_ntt_b_len);

  coefficient_vector sample_ntt_out(p.q_, p.n_);
  for (int i = 0; i < p.n_; i++) {
    sample_ntt_out.c_[i] = 0;
  }
  int n_b = crypto_get_random_bytes(sample_ntt_b_len, sample_ntt_b);
  if (n_b != sample_ntt_b_len) {
    printf("Could not get enough random bits\n");
    return false;
  }
  if (!sample_ntt(p.q_, p.n_, sample_ntt_b_len, 
                  sample_ntt_b, sample_ntt_out.c_)) {
    printf("Could not sample_ntt\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("\nrandom bytes sample_ntt:\n");
    print_bytes(sample_ntt_b_len, sample_ntt_b);
    printf("\nsample ntt out:\n");
    print_coefficient_vector(sample_ntt_out);
    printf("\n");
  }

  int sample_cbd_b_len = 64 * p.eta1_;
  byte_t sample_cbd_b[sample_cbd_b_len];
  memset(sample_cbd_b, 0, sample_cbd_b_len);
  coefficient_vector sample_cbd_out(p.q_, p.n_);
  for (int i = 0; i < p.n_; i++) {
    sample_cbd_out.c_[i] = 0;
  }
  n_b = crypto_get_random_bytes(sample_cbd_b_len, sample_cbd_b);
  if (!sample_poly_cbd(p.q_, p.eta1_, sample_cbd_b_len, sample_cbd_b,
        sample_cbd_out.c_)) {
    printf("Could not sample_poly_cbd\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("\nrandom input poly:\n");
    print_bytes(sample_cbd_b_len, sample_cbd_b);
    printf("\n");
    printf("\nsample poly out:\n");
    print_coefficient_vector(sample_cbd_out);
    printf("\n\n");
  }

  coefficient_vector ntt_in(p.q_, p.n_);
  coefficient_vector ntt_out(p.q_, p.n_);
  coefficient_vector ntt_inv_out(p.q_, p.n_);
  if (!coefficient_vector_zero(&ntt_in)) {
    printf("Cant zero ntt_in\n");
    return false;
  }
  if (!coefficient_vector_zero(&ntt_out)) {
    printf("Cant zero ntt_out");
    return false;
  }
  if (!coefficient_vector_zero(&ntt_inv_out)) {
    printf("Cant zero ntt_inv_out");
    return false;
  }
  for (int i = 0; i < p.n_; i++) {
    ntt_in.c_[i] = i;
  }

  if (!ntt(g, ntt_in, &ntt_out)) {
    printf("Could not ntt transfom\n");
    return false;
  }
  if (!ntt_inv(g, ntt_out, &ntt_inv_out)) {
    printf("Could not inverse ntt transfom\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("\nntt in: \n");
    printf(" ");
    print_coefficient_vector(ntt_in);
    printf("\n");
    printf("\nntt out:\n");
    printf(" ");
    print_coefficient_vector(ntt_out);
    printf("\n");
    printf("\nntt inv out: \n");
    printf(" ");
    print_coefficient_vector(ntt_inv_out);
    printf("\n");
  }

  for (int i = 0; i < 256; i++) {
    if (ntt_in.c_[i] !=  ntt_inv_out.c_[i]) {
      printf("input and ntt_inv(ntt(input)) do not match at %d\n", i);
      return false;
    }
  }

  coefficient_vector m_out(p.q_, p.n_);
  if (!multiply_ntt(g, ntt_in, ntt_in, &m_out)) {
    printf("Could not inverse multiply_ntt\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("\n");
    print_coefficient_vector(ntt_in);
    printf("\n");
    printf(" x_ntt\n");
    print_coefficient_vector(ntt_in);
    printf(" =\n");
    print_coefficient_vector(m_out);
    printf("\n");
  }

  module_array B(p.q_, p.n_, 4, 4);
  module_vector vb1(p.q_, p.n_, 4);
  module_vector vb2(p.q_, p.n_, 4);

  if (!make_module_array_zero(B)) {
    return false;
  }
  if (!make_module_vector_zero(&vb1)) {
    return false;
  }
  if (!make_module_vector_zero(&vb2)) {
    return false;
  }
  for (int i = 0; i < 4; i++) {
    B.c_[B.index(i,i)]->c_[0] = 1;
  }
  B.c_[B.index(0,1)]->c_[0] = 1;

  vb1.c_[0]->c_[0] = 1;
  vb1.c_[1]->c_[0] = 1;
  vb1.c_[2]->c_[0] = 1;
  vb1.c_[3]->c_[0] = 1;
  if (!module_apply_array(B, vb1, &vb2)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("First apply:\n");
    print_module_vector(vb2);
    printf("\n");
  }
  if (vb2.c_[0]->c_[0] != 2 || vb2.c_[1]->c_[0] != 1) {
    printf("module_apply_array failed\n");
    return false;
  }
  if (!make_module_vector_zero(&vb2)) {
    return false;
  }
  if (!module_apply_transposed_array(B, vb1, &vb2)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("Second apply:\n");
    print_module_vector(vb2);
    printf("\n");
  }
  if (vb2.c_[0]->c_[0] != 1 || vb2.c_[1]->c_[0] != 2) {
    printf("module_apply_transposed_array failed\n");
    return false;
  }

  vb1.c_[0]->c_[0] = 1;
  vb1.c_[1]->c_[0] = 1;
  vb1.c_[2]->c_[0] = 1;
  vb1.c_[3]->c_[0] = 1;
  vb2.c_[0]->c_[0] = 1;
  vb2.c_[1]->c_[0] = -1;
  vb2.c_[2]->c_[0] = 1;
  vb2.c_[3]->c_[0] = 1;
  coefficient_vector cv1(p.q_, p.n_);
  coefficient_vector_zero(&cv1);
  if (!module_vector_dot_product(vb1, vb2, &cv1)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("Dot product:\n");
    print_coefficient_vector(cv1);
    printf("\n");
  }

  int a1, a2;
  int m1, m2;
  int r1, r2;
  int z;

  z = 17;
  a1 = 1;
  a2 = 2;
  m1 = 3;
  m2 = 4;
  if (!ntt_base_mult(p.q_, z, a1, a2, m1, m2, &r1, &r2)) {
    printf("ntt_base_mult failed\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("\nntt_base_mult(mod(%d), %d, [%d + %dX] x [%d + %dX] = [%d + %dX] mod(x^2 - %d)\n",
        p.q_, z, a1, a2, m1, m2, r1, r2, z);
    printf("\n");
  }
  if (r1 != 139 || r2 != 10) {
    printf("ntt_base_mult got wrong answer\n");
    return false;
  }

  int prod = 1;
  // int gamma[128];
  for (int i = 0; i < 128; i++) {
    int z;
    int k =((int) bit_reverse(i) >> 1);
    k = 2 * k + 1;
    z = exp_in_ntt(in1.q_, k, g);
    // gamma[i] = z;
    if (FLAGS_print_all) {
      printf("g: %d, i: %3d, bit_rev(7,i): %3d, 2 * bitrev(i) + 1: %3d, g^(%3d): %4d\n",
          g, i, ((int) bit_reverse(i) >> 1), k, k, z);
    }
    prod = (z * prod) % p.q_;
  }
  if (FLAGS_print_all) {
    printf("prod: %d\n\n", prod);
  }
  if (prod != 1) {
    printf("product of poly const terms is wrong\n");
    return false;
  }

  // check that f x h (in normal domain) = ntt_inv(f_ntt x h_ntt)) where mult is in ntt_domain
  coefficient_vector f(p.q_, p.n_);
  coefficient_vector h(p.q_, p.n_);
  coefficient_vector f_ntt(p.q_, p.n_);
  coefficient_vector h_ntt(p.q_, p.n_);
  coefficient_vector product(p.q_, p.n_);
  coefficient_vector product_ntt(p.q_, p.n_);
  coefficient_vector transformed_product_ntt(p.q_, p.n_);

  if (!coefficient_vector_zero(&f)) {
    return false;
  }
  if (!coefficient_vector_zero(&h)) {
    return false;
  }
  if (!coefficient_vector_zero(&product)) {
    return false;
  }
  f.c_[255] = 1;
  h.c_[1] = 1;
  if (!coefficient_mult(f, h, &product)) {
    printf("f x h coefficient_mult fails\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("f:\n");
    print_coefficient_vector(f);
    printf("\n");
    printf("h:\n");
    print_coefficient_vector(h);
    printf("\n");
    printf("f x h:\n");
    print_coefficient_vector(product);
    printf("\n");
  }
  if (product.c_[0] != (p.q_ - 1)) {
    printf("wrong answer f x h\n");
    return false;
  }

  h.c_[2] = 1;
  if (!coefficient_mult(f, h, &product)) {
    printf("f x h coefficient_mult fails\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("f:\n");
    print_coefficient_vector(f);
    printf("\n");
    printf("h:\n");
    print_coefficient_vector(h);
    printf("\n");
    printf("f x h:\n");
    print_coefficient_vector(product);
    printf("\n");
  }

  if (!coefficient_vector_zero(&product)) {
    return false;
  }
  h.c_[255] = 1;
  if (!coefficient_mult(f, h, &product)) {
    printf("f x h coefficient_mult fails\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("f:\n");
    print_coefficient_vector(f);
    printf("\n");
    printf("h:\n");
    print_coefficient_vector(h);
    printf("\n");
    printf("f x h:\n");
    print_coefficient_vector(product);
    printf("\n");
  }
  if (!coefficient_vector_zero(&f)) {
    return false;
  }
  if (!coefficient_vector_zero(&h)) {
    return false;
  }
  if (!coefficient_vector_zero(&product)) {
    return false;
  }

#if 0
  f.c_[0] = 1;
  h.c_[0] = 1;
#else
  for (int i = 0; i < f.len_; i++) {
    /*
    f.c_[i] = i;
    h.c_[i] = f.len_ - i;
     */
    f.c_[i] = 1;
    h.c_[i] = 1;
  }
#endif
  if (!ntt(g, f, &f_ntt)) {
    printf("f x h ntt transform fails\n");
    return false;
  }
  if (!ntt(g, h, &h_ntt)) {
    printf("f x h ntt transform fails\n");
    return false;
  }
  if (!coefficient_mult(f, h, &product)) {
    printf("f x h coefficient_mult fails\n");
    return false;
  }
  if (!multiply_ntt(g, f_ntt, h_ntt, &product_ntt)) {
    printf("f x h multiply_ntt fails\n");
    return false;
  }
  if (!ntt_inv(g, product_ntt, &transformed_product_ntt)) {
    printf("f x h ntt transform fails\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("f:\n");
    print_coefficient_vector(f);
    printf("\n");
    printf("h:\n");
    print_coefficient_vector(h);
    printf("\n");
    printf("f x h:\n");
    print_coefficient_vector(product);
    printf("\n");
    printf("f_ntt:\n");
    print_coefficient_vector(f_ntt);
    printf("\n");
    printf("h_ntt:\n");
    print_coefficient_vector(h_ntt);
    printf("\n");
    printf("f_ntt x h_ntt:\n");
    print_coefficient_vector(product_ntt);
    printf("\n");
    printf("ntt_inv(f_ntt x h_ntt):\n");
    print_coefficient_vector(transformed_product_ntt);
    printf("\n");
  }

  // product and transformed_product_ntt should be the same
  if (!coefficient_equal(product, transformed_product_ntt)) {
    printf("f x h != ntt_inv(f_ntt x h_ntt\n");
    return false;
  }

  return true;
}

TEST (support, test_kyber_support) {
  EXPECT_TRUE(test_kyber_support());
}
TEST (kyber, test_kyber1) {
  EXPECT_TRUE(test_kyber1());
}


int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!init_crypto()) {
    printf("init_crypto failed\n");
    return 1;
  }

  int result = RUN_ALL_TESTS();

  close_crypto();
  printf("\n");
  return 0;
}
