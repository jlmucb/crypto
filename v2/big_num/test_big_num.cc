//
// Copyright 2014 John Manferdelli, All Rights Reserved.
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
// File: big_num_test.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include "crypto_support.h"
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "big_num.h"
#include "intel_digit_arith.h"

DEFINE_bool(print_all, false, "Print intermediate test computations");

bool basic_digit_test1() {
  uint64_t d1[10];
  uint64_t d2[10];
  uint64_t d3[10];
  uint64_t d4[10];
  uint64_t d5[10];

  digit_array_zero_num(10, d1);
  digit_array_zero_num(10, d2);
  if (!digit_array_is_zero(10, d1))
    return false;
  if (digit_array_compare(10, d1, 10, d2) != 0)
    return false;
  if (digit_array_real_size(10, d1) != 1)
    return false;
  d1[0] = 1;
  if (digit_array_real_size(10, d1) != 1)
    return false;
  d1[1] = 1;
  if (digit_array_real_size(10, d1) != 2)
    return false;
  d2[0] = 9;
  if (digit_array_compare(10, d2, 10, d1) != (-1))
    return false;
  if (!digit_array_copy(10, d1, 10, d3))
    return false;
  if (digit_array_compare(10, d1, 10, d3) != 0)
    return false;
  digit_array_zero_num(10, d3);
  digit_array_zero_num(10, d4);
  digit_array_zero_num(10, d5);
  if (FLAGS_print_all) {
    printf("d1               :"); digit_array_print(10, d1); printf("\n");
  }
  if (digit_array_shift_up(10, d1, 2, 10, d3) < 0)
    return false;
  if (FLAGS_print_all) {
    printf("shifted up by 2  :"); digit_array_print(10, d3); printf("\n");
  }
  if (digit_array_shift_down(10, d3, 2, 10, d4) < 0)
    return false;
  if (FLAGS_print_all) {
    printf("d4               :"); digit_array_print(10, d4); printf("\n");
  }
  if (digit_array_compare(10, d1, 10, d4) != 0)
    return false;
  digit_array_zero_num(10, d3);
  digit_array_zero_num(10, d4);
  digit_array_zero_num(10, d5);
  if (FLAGS_print_all) {
    printf("d1               :"); digit_array_print(10, d1); printf("\n");
  }
  if (digit_array_shift_up(10, d1, 66, 10, d3) < 0)
    return false;
  if (FLAGS_print_all) {
    printf("shifted up by 66 :"); digit_array_print(10, d3); printf("\n");
  }
  if (digit_array_shift_down(10, d3, 66, 10, d4) < 0)
    return false;
  if (FLAGS_print_all) {
    printf("d4               :"); digit_array_print(10, d4); printf("\n");
  }
  if (digit_array_compare(10, d1, 10, d4) != 0)
    return false;

  return true;
}

/*
void u64_add_step(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry);
void u64_mult_step(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry);
void u64_div_step(uint64_t a, uint64_t b, uint64_t c, uint64_t* result, uint64_t* carry);
void u64_add_with_carry_step(uint64_t a, uint64_t b, uint64_t carry_in,
                            uint64_t* result, uint64_t* carry_out);
void u64_sub_with_borrow_step(uint64_t a, uint64_t b, uint64_t borrow_in,
                             uint64_t* result, uint64_t* borrow_out);
void u64_mult_with_carry_step(uint64_t a, uint64_t b, uint64_t carry1,
                             uint64_t carry2, uint64_t* result, uint64_t* carry_out);
 */
/*
int digit_array_add_to(int capacity_a, int size_a, uint64_t* a, int size_b,
                    uint64_t* b);
int digit_array_sub_from(int capacity_a, int size_a, uint64_t* a, int size_b, uint64_t* b);
int digit_array_square(int size_a, uint64_t* a, int size_result, uint64_t* result);
int digit_array_mult_by(int capacity_a, int size_a, uint64_t* a, uint64_t x);
bool digit_array_short_division_algorithm(int size_a, uint64_t* a, uint64_t b,
                                      int* size_q, uint64_t* q, uint64_t* r);
void estimate_quotient(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t b1,
                       uint64_t b2, uint64_t* est);
bool digit_array_division_algorithm(int size_a, uint64_t* a, int size_b,
       uint64_t* b, int* size_q, uint64_t* q, int* size_r, uint64_t* r);
*/
bool basic_digit_test2() {
  uint64_t n1[10];
  uint64_t n2[10];
  uint64_t n3[10];
  uint64_t n4[10];
  uint64_t n5[10];
  uint64_t one[1];
  one[0] = 1ULL;
  uint64_t two[1];
  two[0] = 2ULL;
  
  digit_array_zero_num(10, n1);
  digit_array_zero_num(10, n2);

  digit_array_zero_num(10, n3);
  if (digit_array_add(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (!digit_array_is_zero(10, n3))
    return false;
  digit_array_zero_num(10, n3);
  if (digit_array_sub(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (!digit_array_is_zero(10, n3))
    return false;
  digit_array_zero_num(10, n3);
  if (digit_array_mult(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (!digit_array_is_zero(10, n3))
    return false;

  n1[0] = 1;
  digit_array_zero_num(10, n3);
  if (digit_array_add(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (digit_array_compare(1, one, 10, n3) != 0)
    return false;
  digit_array_zero_num(10, n3);
  if (digit_array_sub(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (digit_array_compare(1, one, 10, n3) != 0)
    return false;
  digit_array_zero_num(10, n3);
  if (digit_array_mult(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (!digit_array_is_zero(10, n3))
    return false;

  n2[0] = 1;
  digit_array_zero_num(10, n3);
  if (digit_array_add(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (digit_array_compare(1, two, 10, n3) != 0)
    return false;
  digit_array_zero_num(10, n3);
  if (digit_array_sub(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (!digit_array_is_zero(10, n3))
    return false;
  digit_array_zero_num(10, n3);
  if (digit_array_mult(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (digit_array_compare(1, one, 10, n3) != 0)
    return false;

  n1[1] = 0xffffffffffff07;
  n2[1] = 0xffffffffffff05;
  digit_array_zero_num(10, n3);
  if (digit_array_add(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" + ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  digit_array_zero_num(10, n3);
  if (digit_array_sub(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" - ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  digit_array_zero_num(10, n3);
  if (digit_array_mult(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" * ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  return true;
}

bool decimal_convert_test1() {
  uint64_t n[2];
  n[0]= 301;
  n[1]= 1;
  string s;
  uint64_t m[3];

  digit_array_zero_num(3, m);
  if (!digit_convert_to_decimal(1, n, &s))
    return false;
  if (!digit_convert_from_decimal(s, 2, m))
    return false;
  if (digit_array_compare(1, n, 2, m) != 0)
    return false;
  if (FLAGS_print_all)
    printf("n: %lld, %s\n", n[0], s.c_str());

  digit_array_zero_num(3, m);
  if (!digit_convert_to_decimal(2, n, &s))
    return false;
  if (!digit_convert_from_decimal(s, 3, m))
    return false;
  if (digit_array_compare(2, n, 3, m) != 0)
    return false;

  if (FLAGS_print_all) 
    printf("n: %lld %lld, %s\n", n[1], n[0], s.c_str());
  return true;

}

/*
  big_num(int size);
  big_num(big_num& n);
  big_num(big_num& n, int capacity);
  big_num(int size, uint64_t);  // big_num with one initialized digit
  ~big_num();
  int capacity();  // total number of digits (64 bits) allocated
  int size();      // number of digit required to hold current value
  uint64_t* value_ptr();
  bool is_positive();
  bool is_zero();
  bool is_one();
  bool is_negative();
  void toggle_sign();
  void normalize();
  void zero_num();
  bool copy_from(big_num&);
  bool copy_to(big_num&);

extern uint64_t smallest_primes[];
extern big_num big_zero;
extern big_num big_one;
extern big_num big_two;
extern big_num big_three;
extern big_num big_four;
extern big_num big_five;
*/
bool basic_big_num_test1() {
  return true;
}

/*
int big_compare(big_num& l, big_num& r);
int big_high_digit(big_num& a);
bool big_bit_position_on(big_num& a, int n);
int big_max_power_of_two_dividing(big_num& a);
bool big_shift(big_num& a, int64_t shift, big_num& r);
bool big_unsigned_add(big_num& a, big_num& b, big_num& r);
bool big_unsigned_sub(big_num& a, big_num& b, big_num& r);
bool big_unsigned_mult(big_num& a, big_num& b, big_num& r);
bool big_unsigned_euclid(big_num& a, big_num& b, big_num& q, big_num& r);
bool big_unsigned_div(big_num& a, big_num& b, big_num& q);
bool big_unsigned_square(big_num& a, big_num& r);
bool big_unsigned_add_to(big_num& a, big_num& b);
bool big_unsigned_sub_from(big_num& a, big_num& b);
bool big_unsigned_inc(big_num& a);
bool big_unsigned_dec(big_num& a);
bool big_add(big_num& a, big_num& b, big_num& r);
bool big_sub(big_num& a, big_num& b, big_num& r);
bool big_mult(big_num& a, big_num& b, big_num& r);
bool big_div(big_num& a, big_num& b, big_num& r);
bool big_square(big_num& a, big_num& r);
bool convert_to_decimal(int size_a, uint64_t* n, string* s);
big_num* big_convert_from_decimal(string& s);
bool big_convert_to_hex(big_num& a, string* hex);
big_num* big_convert_from_hex(const char* in);
*/
bool basic_arith_test1() {
  return true;
}

/*
bool big_extended_gcd(big_num& a, big_num& b, big_num& x, big_num& y, big_num& g);
bool big_crt(big_num& s1, big_num& s2, big_num& m1, big_num& m2, big_num& r);
bool big_mod(big_num& a, big_num& m, big_num& r);
bool big_mod_add(big_num& a, big_num& b, big_num& m, big_num& r);
bool big_mod_neg(big_num& a, big_num& m, big_num& r);
bool big_mod_neg(big_num& a, big_num& m, big_num& r);
bool big_mod_mult(big_num& a, big_num& b, big_num& m, big_num& r);
bool big_mod_square(big_num& a, big_num& m, big_num& r);
bool big_mod_div(big_num& a, big_num& b, big_num& m, big_num& r);
bool big_mod_exp(big_num& a, big_num& e, big_num& m, big_num& r);
bool big_gen_prime(big_num& p, uint64_t num_bits, int prime_trys=2500);
int big_high_bit(big_num& a);
bool big_miller_rabin(big_num& n, big_num** random_a, int trys);
bool big_is_prime(big_num& n);
bool big_mod_is_square(big_num& n, big_num& p);
bool big_mod_tonelli_shanks(big_num& a, big_num& p, big_num& s);
bool big_mod_square_root(big_num& n, big_num& p, big_num& r);
bool big_make_mont(big_num& a, int r, big_num& m, big_num& mont_a);
bool big_mont_params(big_num& m, int r, big_num& m_prime);
bool big_mont_reduce(big_num& a, int r, big_num& m, big_num& m_prime, big_num& mont_a);
bool big_mont_mult(big_num& aR, big_num& bR, big_num& m, uint64_t r, big_num& m_prime,
                 big_num& abR);
bool big_mont_exp(big_num& b, big_num& e, int r, big_num& m, big_num& m_prime, big_num& out);
bool big_mod_normalize(big_num& a, big_num& m);
 */
bool basic_number_theory_test1() {
  return true;
}

TEST(digit_tests, set1) {
  EXPECT_TRUE(basic_digit_test1());
}
TEST(digit_tests, set2) {
  EXPECT_TRUE(basic_digit_test2());
}
TEST(decimal, convert) {
  EXPECT_TRUE(decimal_convert_test1());
}
TEST(big_num, basic_arith_test1) {
  EXPECT_TRUE(basic_big_num_test1());
}
TEST(big_num, basic_test1) {
  EXPECT_TRUE(basic_big_num_test1());
}
TEST(big_num, basic_arith_test) {
  EXPECT_TRUE(basic_arith_test1());
}
TEST(big_num, basic_number_theory_test) {
  EXPECT_TRUE(basic_number_theory_test1());
}

int main(int an, char** av) {

  uint64_t cycles_per_second = calibrate_rdtsc();
  printf("This computer has %llu cycles per second\n", cycles_per_second);

  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!init_crypto()) {
    printf("Can't init_crypto\n");
    return 1;
  }

  int result = RUN_ALL_TESTS();
  printf("%d Tests complete\n", result);

  close_crypto();
  return 1;
}

