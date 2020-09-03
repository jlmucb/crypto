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
#include "big_num_functions.h"

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
  // add: 01fffffffffffe0c 0000000000000002
  // sub: 0000000000000002 0000000000000000
  // mult: 0000fffffffffffe 0c0000000000f423 01fffffffffffe0c 0000000000000001
  uint64_t add_cmp[2] = {0x0000000000000002ULL, 0x01fffffffffffe0cULL};
  uint64_t sub_cmp[2] = {0x00ULL, 0x02ULL};
  uint64_t mult_cmp[4] = {0x0000000000000001ULL, 0x01fffffffffffe0cULL, 0x0c0000000000f423ULL, 0x0000fffffffffffe };
  digit_array_zero_num(10, n3);
  if (digit_array_add(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" + ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(2, add_cmp, 10, n3) != 0)
    return false;
  digit_array_zero_num(10, n3);
  if (digit_array_sub(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" - ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(2, sub_cmp, 10, n3) != 0)
    return false;
  digit_array_zero_num(10, n3);
  if (digit_array_mult(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" * ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(4, mult_cmp, 10, n3) != 0)
    return false;

  digit_array_zero_num(10, n4);
  digit_array_zero_num(10, n5);
  int size_q = 10;
  int size_r = 10;
  if (!digit_array_division_algorithm(10, n3, 10,
         n1, &size_q, n4, &size_r, n5))
    return false;
  if (FLAGS_print_all) {
    digit_array_print(10, n3); printf(" / ");
    digit_array_print(10, n1); printf(" = ");
    digit_array_print(10, n4); printf("\n");
  }
  if (digit_array_compare(10, n4, 10, n2) != 0)
    return false;

  uint64_t addc_cmp[2] = {
    0xfffffffffffffffeULL, 0x0000000000000004ULL
  };
  uint64_t subc_cmp[2] = {
    0ULL,
    1ULL
  };
  uint64_t multc_cmp[3] = {
    0x0000000000000001ULL,
    0xfffffffffffffffbULL,
    0x0000000000000005ULL
  };
  digit_array_zero_num(10, n1);
  digit_array_zero_num(10, n2);
  digit_array_zero_num(10, n3);
  digit_array_zero_num(10, n4);
  n1[0] = 0xffffffffffffffffULL;
  n1[1] = 0x02;
  n2[0] = 0xffffffffffffffffULL;
  n2[1] = 0x01;
  if (digit_array_add(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" + ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(2, addc_cmp, 10, n3) != 0)
    return false;
  digit_array_zero_num(10, n3);
  if (digit_array_sub(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" - ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(2, subc_cmp, 10, n3) != 0)
    return false;
  digit_array_zero_num(10, n3);
  if (digit_array_mult(10, n1, 10, n2, 10, n3) < 0)
    return false;
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" * ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(3, multc_cmp, 10, n3) != 0)
    return false;

  // void estimate_quotient(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t b1,
  //                     uint64_t b2, uint64_t* est);

  digit_array_zero_num(10, n1);
  digit_array_zero_num(10, n2);
  n1[1] = 1ULL;
  size_q = 10;
  uint64_t rr = 0ULL;
  if (!digit_array_short_division_algorithm(10, n1, 5ULL, &size_q, n2, &rr))
    return false;
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" /  %lld = ", 5ULL);
    digit_array_print(size_q, n2); printf(", remainder %lld\n", rr);
  }
  if (rr != 1ULL)
    return false;
  
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

bool basic_big_num_test1() {
  big_num a(10, 1ULL);

  if (a.size() != 1 || a.capacity() != 10)
    return false;
  a.size_ = 4;
  a.normalize();
  if (a.size() != 1 || a.capacity() != 10)
    return false;
  if (!a.is_positive() || a.is_negative())
    return false;
  if (big_compare(a, big_one) != 0 || big_compare(a, big_two) != -1)
    return false;
  if (big_compare(a, big_one) != 0 || big_compare(a, big_zero) != 1)
    return false;
  a.toggle_sign();
  if (a.is_positive() || !a.is_negative())
    return false;
  a.zero_num();
  if (!a.is_zero())
    return false;

  big_num b(10);
  big_num c(10);
  a.copy_to(b);
  c.copy_from(a);
  if (big_compare(b, c) != 0)
    return false;

  return true;
}

bool basic_arith_test1() {
  big_num a(5, 2ULL);
  a.value_ptr()[1] = 0x08;
  a.normalize();

  digit_array_print(a.size(), a.value_ptr());
  int k = big_high_digit(a);
  if (k != 2)
    return false;
  if (FLAGS_print_all) 
    printf(", high digit: %d, ", k);
  k = big_high_bit(a);
  if (FLAGS_print_all) 
    printf("high bit: %d, ", k);
  if (k != 68)
    return false;
  if (!big_bit_position_on(a, 2))
    return false;
  if (!big_bit_position_on(a, 68))
    return false;
  k = big_max_power_of_two_dividing(a);
  if (FLAGS_print_all) 
    printf("power of 2: %d\n", k);
  big_num b(10);
  big_num c(10);
  if (!big_shift(a, 10, b))
    return false;
  if (!big_shift(b, -10, c))
    return false;
  if (FLAGS_print_all)  {
    a.print(); printf(" shifted %d ", 10);
    b.print(); printf(" shifted %d ", -10);
    c.print(); printf("\n");
  }
  if (big_compare(a, c) != 0)
    return false;
  string decimal_str;
  if (!digit_convert_to_decimal(b.size(), b.value_ptr(), &decimal_str))
    return false;
  if (FLAGS_print_all)  {
    b.print(); printf(" as decimal is %s\n", decimal_str.c_str());
  }
  big_num* d = big_convert_from_decimal(decimal_str);
  if (d == nullptr)
    return false;
  if (FLAGS_print_all)  {
    d->print(); printf(" converted back\n");
  }
  if (big_compare(b, *d) !=0)
    return false;
  delete d;
  d = nullptr;

  string hex_str;
  if (!big_convert_to_hex(b, &hex_str))
    return false;
  if (FLAGS_print_all)  {
    b.print(); printf(" as hex is %s\n", hex_str.c_str());
  }
  d = big_convert_from_hex(hex_str.c_str());
  if (d == nullptr)
    return false;
  if (FLAGS_print_all)  {
    d->print(); printf(" converted back\n");
  }
  if (big_compare(b, *d) !=0)
    return false;
  delete d;
  d = nullptr;

  if (FLAGS_print_all)  {
    a.print();
  }
  if (!big_unsigned_inc(a))
    return false;
  if (FLAGS_print_all)  {
    printf(" incremented: "); a.print();
  }
  if (!big_unsigned_dec(a))
    return false;
  if (FLAGS_print_all)  {
    printf(" incremented: "); a.print();
  }

  big_num n1(10);
  big_num n2(10);
  big_num q(10);
  big_num r(10);

  n1.value_ptr()[0] = 0xffffffffffffffff;
  n1.value_ptr()[1] = 0xff;
  n2.value_ptr()[0] = 0xffffffffffffffff;
  n2.value_ptr()[1] = 0x05;
  n1.normalize();
  n2.normalize();
  if (!big_unsigned_add(n1, n2, r))
    return false;
  if (FLAGS_print_all)  {
    n1.print(); printf(" + ");
    n2.print(); printf(" = ");
    r.print(); printf("\n");
  }
  big_num add_cmp(2);
  add_cmp.value_ptr()[0] = 0xfffffffffffffffe;
  add_cmp.value_ptr()[1] = 0x0000000000000105;
  add_cmp.normalize();
  if (big_compare(add_cmp, r) != 0)
    return false;
  r.zero_num();
  if (!big_unsigned_sub(n1, n2, r))
    return false;
  if (FLAGS_print_all)  {
    n1.print(); printf(" - ");
    n2.print(); printf(" = ");
    r.print(); printf("\n");
  }
  big_num sub_cmp(2);
  sub_cmp.value_ptr()[0] = 0x0;
  sub_cmp.value_ptr()[1] = 0xfa;
  sub_cmp.normalize();
  if (big_compare(sub_cmp, r) != 0)
    return false;
  r.zero_num();
  if (!big_unsigned_mult(n1, n2, r))
    return false;
  if (FLAGS_print_all)  {
    n1.print(); printf(" * ");
    n2.print(); printf(" = ");
    r.print(); printf("\n");
  }
  big_num mult_cmp(3);
  mult_cmp.value_ptr()[0] = 1ULL;
  mult_cmp.value_ptr()[1] = 0xfffffffffffffefaULL;
  mult_cmp.value_ptr()[2] = 0x00000000000005ffULL;
  mult_cmp.normalize();
  if (big_compare(mult_cmp, r) != 0)
    return false;
  r.zero_num();
  if (!big_unsigned_euclid(n1, n2, q, r))
    return false;
  if (FLAGS_print_all)  {
    n1.print(); printf(" = ");
    n2.print(); printf(" * ");
    q.print(); printf(", remainder: ");
    r.print(); printf("\n");
  }
  big_num rem_cmp(2);
  rem_cmp.value_ptr()[0] = 0x0000000000000029ULL;
  rem_cmp.value_ptr()[1] = 0x0000000000000004;
  rem_cmp.normalize();
  if (big_compare(rem_cmp, r) != 0 || q.value_ptr()[0] != 0x2aULL)
     return false;
  q.zero_num();
  if (!big_unsigned_div(n1, n2, q))
    return false;
  if (FLAGS_print_all)  {
    n1.print(); printf(" = ");
    n2.print(); printf(" * ");
    q.print(); printf("\n");
  }
  if (q.value_ptr()[0] != 0x2aULL)
     return false;
  q.zero_num();
return true;
  if (!big_unsigned_square(n1, r))
    return false;
  if (!big_unsigned_add_to(n1, b))
    return false;
  if (!big_unsigned_sub_from(n1, n2))
    return false;

  if (!big_add(n1, n2, r))
    return false;
  if (!big_sub(n1, n2, r))
    return false;
  if (!big_mult(n1, n2, r))
    return false;
  if (!big_div(n1, n2, r))
    return false;
  if (!big_square(n1, r))
    return false;

  return true;
}

bool basic_number_theory_test1() {
  big_num a(10);
  big_num b(10);
  big_num g(10);
  big_num m(10);
  big_num n(10);
  big_num x(10);
  big_num y(10);
  big_num r(10);
  big_num p(10);
  big_num e(10);
  big_num s(10);
  big_num c1(10);
  big_num c2(10);
  big_num n1(10);
  big_num n2(10);

return true;
  if (!big_extended_gcd(a, b, x, y, g))
    return false;
  if (!big_crt(n1, n2, c1, c2, r))
    return false;
  if (!big_mod_normalize(a, m))
    return false;
  if (!big_mod(a, m, r))
    return false;
  if (!big_mod_add(a, b, m, r))
    return false;
  if (!big_mod_neg(a, m, r))
    return false;
  if (!big_mod_mult(a, b, m, r))
    return false;
  if (!big_mod_square(a, m, r))
    return false;
  if (!big_mod_div(a, b, m, r))
    return false;
  if (!big_mod_exp(a, e, m, r))
    return false;
  int num_bits = 1024;
  if (!big_gen_prime(p, num_bits, 25))
    return false;
  if (!big_high_bit(a))
    return false;
  // if (!big_miller_rabin(n, random_a, 20))
  if (!big_is_prime(n))
    return false;
  if (!big_mod_is_square(n, p))
    return false;
  if (!big_mod_tonelli_shanks(a, p, s))
    return false;
  if (!big_mod_square_root(n, p, r))
    return false;
  // if (!big_make_mont(a, int r, m, mont_a))
  // if (!big_mont_params(m, int r, m_prime))
  // if (!big_mont_reduce(big_num& a, int r, big_num& m, big_num& m_prime, big_num& mont_a))
  // if (!big_mont_mult(big_num& aR, big_num& bR, big_num& m, uint64_t r, big_num& m_prime, big_num& abR))
  // if (!bool big_mont_exp(big_num& b, big_num& e, int r, big_num& m, big_num& m_prime, big_num& out))

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

  close_crypto();
  return 1;
}

