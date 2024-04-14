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

  int ek_len = 384 * p.k_ + 32;
  byte ek[ek_len];
  memset(ek, 0, ek_len);
  int dk_len = 384 * p.k_;
  byte dk[dk_len];
  memset(dk, 0, dk_len);
  if (!kyber_keygen(p, &ek_len, ek, &dk_len, dk)) {
    printf("Could not init kyber_keygen\n");
    return false;
  }

  int m_len = 32;
  byte m[m_len];
  int r_len = 32;
  byte r[r_len];
  int c_len = 32 * (p.du_ * p.k_ + p.dv_);
  byte c[c_len];
  memset(m, 0, m_len);
  memset(c, 0, c_len);
  memset(r, 0, r_len);
  if (!kyber_encrypt(p, ek_len, ek, m_len, m, &c_len, c)) {
    printf("Could not init kyber_encrypt\n");
    return false;
  }
  int recovered_m_len = 32;
  byte recovered_m[m_len];
  memset(recovered_m, 0, recovered_m_len);
  if (!kyber_decrypt(p, dk_len, dk, c_len, c, &recovered_m_len, recovered_m)) {
    printf("Could not init kyber_decrypt\n");
    return false;
  }
  if (memcmp(m, recovered_m, m_len) != 0) {
    printf("message and recovered message dont match\n");
    return false;
  }

  int kem_ek_len = 384 * p.k_ + 32;
  byte kem_ek[kem_ek_len];
  memset(kem_ek, 0, kem_ek_len);
  int kem_dk_len = 768 * p.k_ + 96;
  byte kem_dk[kem_dk_len];
  memset(kem_dk, 0, kem_dk_len);
  if (!kyber_kem_keygen(p, &kem_ek_len, kem_ek, &kem_dk_len, kem_dk)) {
    printf("Could not init kem_keygen\n");
    return false;
  }
  int kem_c_len = 32 * (p.du_ * p.k_ + p.dv_);
  byte kem_c[kem_dk_len];
  memset(kem_c, 0, kem_c_len);
  int kem_k_len = 32;
  byte kem_k[kem_k_len];
  memset(kem_k, 0, kem_k_len);
  if (!kyber_kem_encaps(p, kem_ek_len, kem_ek, &kem_k_len,
                          kem_k, &kem_c_len, kem_c)) {
    printf("Could not init kem_encaps\n");
    return false;
  }
  int recovered_k_len = 32;
  byte recovered_k[recovered_k_len];
  memset(recovered_k, 0, recovered_k_len);
  if (!kyber_kem_decaps(p, kem_dk_len, kem_dk, kem_c_len, kem_c,
                           &recovered_k_len, recovered_k)) {
    printf("Could not init kem_decaps\n");
    return false;
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

  byte b1, b2;
  b1 = 0xc;
  b2 = bit_reverse(b1);
  if (FLAGS_print_all) {
    printf("%02x reversed is %02x\n", b1, b2);
  }
  if (b2 != 0x30) {
    printf("bit_reverse fail(1)\n");
    return false;
  }

 
  short int e = 4;
  short int base = 2;

  short int ex = exp_in_ntt((short int)q, e, base);
  if (FLAGS_print_all) {
    printf("%d^%d (mod %d) = %d\n", base, e, q, ex);
  }
  if (ex != 16) {
    printf("exp fail (1)\n");
    return false;
  }

  e = 12;
  ex = exp_in_ntt((short int)q, e, base);
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

  /*
  bool ntt_base_mult(short int q, short int g, int& in1, int& in2, int* out);
  bool ntt_base_add(short int q, int& in1, int& in2, int* out);
  bool sample_ntt(int q, int l, byte* b, short int* out);
  bool sample_poly_cbd(int q, int eta, int l, byte* b, short int* out);
  bool ntt(short int g, coefficient_vector& in, coefficient_vector* out);
  bool ntt_inv(short int g, coefficient_vector& in, coefficient_vector* out);
  bool ntt_add(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out);
  bool ntt_mult(short int g, coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out);
*/

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
