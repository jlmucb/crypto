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

  /*
    bool kyber_keygen(kyber_parameters& p, int* ek_len, byte* ek,
      int* dk_len, byte* dk);
    bool kyber_encrypt(kyber_parameters& p, int ek_len, byte* ek,
      int m_len, byte* m, int* c_len, byte* c);
    bool kyber_decrypt(kyber_parameters& p, int dk_len, byte* dk,
      int c_len, byte* c, int* m_len, byte* m);

    bool kyber_kem_keygen(kyber_parameters& p, int* kem_ek_len, byte* kem_ek,
      int* kem_dk_len, byte* kem_dk);
    bool kyber_kem_kem(kyber_parameters& p, int kem_ek_len, byte* kem_ek,
      int* k_len, byte* k, int* c_len, byte* c);
    bool kyber_kem_decaps(kyber_parameters& p, int kem_dk_len, byte* kem_dk,
      int c_len, byte* c, int* k_len, byte* k);
  */

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
