// Copyright 2020 John Manferdelli, All Rights Reserved.
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
void u64_u64_product_step(uint64_t a, uint64_t b, uint64_t carry1,
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
  if (digit_array_add(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 1***\n");
    return false;
  }
  if (!digit_array_is_zero(10, n3)) {
    printf("*****ERROR 2***\n");
    return false;
  }

  digit_array_zero_num(10, n3);
  if (digit_array_sub(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 3***\n");
    return false;
  }
  if (!digit_array_is_zero(10, n3)) {
    digit_array_print(10, n1); printf(" - ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
    printf("*****ERROR 4***\n");
    return false;
  }
  digit_array_zero_num(10, n3);
  if (digit_array_mult(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 5***\n");
    return false;
  }
  if (!digit_array_is_zero(10, n3)) {
    printf("*****ERROR 6***\n");
    return false;
  }

  n1[0] = 1;
  digit_array_zero_num(10, n3);
  if (digit_array_add(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 7***\n");
    return false;
  }
  if (digit_array_compare(1, one, 10, n3) != 0) {
    printf("*****ERROR 8***\n");
    return false;
  }
  digit_array_zero_num(10, n3);
  if (digit_array_sub(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 9***\n");
    return false;
  }
  if (digit_array_compare(1, one, 10, n3) != 0) {
    printf("*****ERROR 10***\n");
    return false;
  }
  digit_array_zero_num(10, n3);
  if (digit_array_mult(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 11***\n");
    return false;
  }
  if (!digit_array_is_zero(10, n3)) {
    printf("*****ERROR 12***\n");
    return false;
  }

  n2[0] = 1;
  digit_array_zero_num(10, n3);
  if (digit_array_add(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 13***\n");
    return false;
  }
  if (digit_array_compare(1, two, 10, n3) != 0) {
    printf("*****ERROR 14***\n");
    return false;
  }
  digit_array_zero_num(10, n3);
  if (digit_array_sub(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 15***\n");
    return false;
  }
  if (!digit_array_is_zero(10, n3)) {
    printf("*****ERROR 16***\n");
    return false;
  }
  digit_array_zero_num(10, n3);
  if (digit_array_mult(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 17***\n");
    return false;
  }
  if (digit_array_compare(1, one, 10, n3) != 0) {
    printf("*****ERROR 18***\n");
    return false;
  }

  n1[1] = 0xffffffffffff07;
  n2[1] = 0xffffffffffff05;
  // add: 01fffffffffffe0c 0000000000000002
  // sub: 0000000000000002 0000000000000000
  // mult: 0000fffffffffffe 0c0000000000f423 01fffffffffffe0c 0000000000000001
  uint64_t add_cmp[2] = {0x0000000000000002ULL, 0x01fffffffffffe0cULL};
  uint64_t sub_cmp[2] = {0x00ULL, 0x02ULL};
  uint64_t mult_cmp[4] = {0x0000000000000001ULL, 0x01fffffffffffe0cULL, 0x0c0000000000f423ULL, 0x0000fffffffffffe };
  digit_array_zero_num(10, n3);
  if (digit_array_add(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 19***\n");
    return false;
  }
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" + ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(2, add_cmp, 10, n3) != 0) {
    printf("*****ERROR 20***\n");
    return false;
  }
  digit_array_zero_num(10, n3);
  if (digit_array_sub(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 21***\n");
    return false;
  }
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" - ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(2, sub_cmp, 10, n3) != 0) {
    printf("*****ERROR 22***\n");
    return false;
  }
  digit_array_zero_num(10, n3);
  if (digit_array_mult(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 23***\n");
    return false;
  }
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" * ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(4, mult_cmp, 10, n3) != 0) {
    printf("*****ERROR 24***\n");
    printf("Should be: ");
    digit_array_print(4, mult_cmp); printf("\n");
    return false;
  }

  digit_array_zero_num(10, n4);
  digit_array_zero_num(10, n5);
  int size_q = 10;
  int size_r = 10;
  if (!digit_array_division_algorithm(10, n3, 10,
         n1, &size_q, n4, &size_r, n5)) {
    printf("*****ERROR 25***\n");
    return false;
  }
  if (FLAGS_print_all) {
    digit_array_print(10, n3); printf(" / ");
    digit_array_print(10, n1); printf(" = ");
    digit_array_print(10, n4); printf("\n");
  }
  if (digit_array_compare(10, n4, 10, n2) != 0) {
    printf("*****ERROR 26***\n");
    return false;
  }

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
  if (digit_array_add(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 27***\n");
    return false;
  }
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" + ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(2, addc_cmp, 10, n3) != 0) {
    printf("*****ERROR 28***\n");
    return false;
  }
  digit_array_zero_num(10, n3);
  if (digit_array_sub(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 29***\n");
    return false;
  }
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" - ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(2, subc_cmp, 10, n3) != 0) {
    printf("*****ERROR 30***\n");
    return false;
  }
  digit_array_zero_num(10, n3);
  if (digit_array_mult(10, n1, 10, n2, 10, n3) < 0) {
    printf("*****ERROR 31***\n");
    return false;
  }
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" * ");
    digit_array_print(10, n2); printf(" = ");
    digit_array_print(10, n3); printf("\n");
  }
  if (digit_array_compare(3, multc_cmp, 10, n3) != 0) {
    printf("*****ERROR 32***\n");
    printf("Should be: ");
    digit_array_print(3, multc_cmp); printf("\n");
    return false;
  }

  // void estimate_quotient(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t b1,
  //                     uint64_t b2, uint64_t* est);

  digit_array_zero_num(10, n1);
  digit_array_zero_num(10, n2);
  n1[1] = 1ULL;
  size_q = 10;
  uint64_t rr = 0ULL;
  if (!digit_array_short_division_algorithm(10, n1, 5ULL, &size_q, n2, &rr)) {
    printf("*****ERROR 33***\n");
    return false;
  }
  if (FLAGS_print_all) {
    digit_array_print(10, n1); printf(" /  %ld = ", 5ULL);
    digit_array_print(size_q, n2); printf(", remainder %ld\n", rr);
  }
  if (rr != 1ULL) {
    printf("*****ERROR 34***  %lx\n", rr);
    return false;
  }
  
  return true;
}

bool decimal_convert_test1() {
  uint64_t n[2];
  n[0]= 301;
  n[1]= 1;
  string s;
  uint64_t m[3];
  s.clear();

  digit_array_zero_num(3, m);
  if (!digit_convert_to_decimal(1, n, &s)) {
    printf("error 1\n");
    return false;
  }
  if (FLAGS_print_all)  {
    printf("n: %ld %ld, %s\n", n[1], n[0], s.c_str());
  }
  if (!digit_convert_from_decimal(s, 2, m)) {
    printf("error 2\n");
    return false;
  }
  if (FLAGS_print_all)  {
    printf("m: "); digit_array_print(2, m); printf("\n");
    printf("n: "); digit_array_print(1, n); printf("\n");
  }
  if (digit_array_compare(1, n, 2, m) != 0) {
    printf("error 3\n");
    return false;
  }
  if (FLAGS_print_all)
    printf("n: %ld, %s\n", n[0], s.c_str());

  digit_array_zero_num(3, m);
  if (!digit_convert_to_decimal(2, n, &s)) {
    printf("error 4\n");
    return false;
  }
  if (FLAGS_print_all)  {
    printf("n: %ld %ld, %s\n", n[1], n[0], s.c_str());
  }
  if (!digit_convert_from_decimal(s, 3, m)) {
    printf("error 5\n");
    return false;
  }
  if (FLAGS_print_all)  {
    printf("m: "); digit_array_print(2, m); printf("\n");
    printf("n: "); digit_array_print(2, n); printf("\n");
  }
  if (digit_array_compare(2, n, 3, m) != 0) {
    printf("error 6\n");
    return false;
  }

  if (FLAGS_print_all) 
    printf("n: %ld %ld, %s\n", n[1], n[0], s.c_str());

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

  if (FLAGS_print_all) 
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
  if (!big_convert_to_hex(b, &hex_str)) {
    printf("big_convert_to_hex fails\n");
    return false;
  }
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
  if (!big_unsigned_inc(a)) {
    printf("big_unsigned_inc fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    printf(" incremented: "); a.print();
  }
  if (!big_unsigned_dec(a)) {
    printf("big_unsigned_dec fails\n");
    return false;
  }
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
  if (!big_unsigned_add(n1, n2, r)) {
    printf("big_unsigned_add fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    n1.print(); printf(" + ");
    n2.print(); printf(" = ");
    r.print(); printf("\n");
  }
  big_num add_cmp(2);
  add_cmp.value_ptr()[0] = 0xfffffffffffffffe;
  add_cmp.value_ptr()[1] = 0x0000000000000105;
  add_cmp.normalize();
  if (big_compare(add_cmp, r) != 0) {
    printf("bad compare 1\n");
    return false;
  }
  r.zero_num();
  if (!big_unsigned_sub(n1, n2, r)) {
    printf("big_unsigned_sub fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    n1.print(); printf(" - ");
    n2.print(); printf(" = ");
    r.print(); printf("\n");
  }
  big_num sub_cmp(2);
  sub_cmp.value_ptr()[0] = 0x0;
  sub_cmp.value_ptr()[1] = 0xfa;
  sub_cmp.normalize();
  if (big_compare(sub_cmp, r) != 0) {
    printf("bad compare 2\n");
    return false;
  }
  r.zero_num();
  if (!big_unsigned_mult(n1, n2, r)) {
    printf("big_unsigned_mult fails\n");
    return false;
  }
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
  if (big_compare(mult_cmp, r) != 0) {
    printf("bad compare 3\n");
    return false;
  }

  r.zero_num();
  q.zero_num();
  if (!big_unsigned_euclid(n1, n2, q, r)) {
    printf("big_unsigned_euclid fails\n");
    return false;
  }
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
  if (big_compare(rem_cmp, r) != 0 || q.value_ptr()[0] != 0x2aULL) {
    printf("bad compare 4\n");
    return false;
  }
  q.zero_num();
  if (!big_unsigned_div(n1, n2, q)) {
    printf("big_unsigned_div fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    n1.print(); printf(" = ");
    n2.print(); printf(" * ");
    q.print(); printf("\n");
  }
  if (q.value_ptr()[0] != 0x2aULL)
     return false;

  q.zero_num();
  big_num n3(10);
  n3.zero_num();
  n3.copy_from(n1);
  n3.normalize();
  
  if (!big_unsigned_add_to(n3, big_five)) {
    printf("big_unsigned_add_to fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    n1.print(); printf(" +=  5 is ");
    n3.print(); printf("\n");
  }
  if (!big_unsigned_sub_from(n3, big_five)) {
    printf("big_unsigned_sub_from fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    printf(" -=  5 is ");
    n3.print(); printf("\n");
  }
  if (big_compare(n1, n3) != 0) {
    printf("bad compare 5\n");
    return false;
  }

  r.zero_num();
  if (!big_unsigned_square(n1, r)) {
    printf("big_unsigned_square fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    n1.print(); printf("**2 = ");
    r.print(); printf("\n");
  }

  big_num b_cmp_sq(3);
  uint64_t cmp_sq[3] = {
    0x1ULL, 0xfffffffffffffe00ULL, 0x000000000000ffffULL
  };
  for (int j = 0; j < 3; j++)
    b_cmp_sq.value_ptr()[j] = cmp_sq[j];
  b_cmp_sq.normalize();
  r.zero_num();
  n1.toggle_sign();
  if (!big_square(n1, r)) {
    printf("big_square fails\n");
    return false;
  }
  if (big_compare(r, b_cmp_sq) != 0)
    return false;

  big_num s_add_cmp(10);
  big_num s_sub_cmp(10);
  big_num s_mult_cmp(10);
  big_num s_div_cmp(10);

  s_add_cmp.value_ptr()[0] = 0x00ULL;
  s_add_cmp.value_ptr()[1] = 0xfaULL;
  s_add_cmp.toggle_sign();
  s_add_cmp.normalize();
  
  s_sub_cmp.value_ptr()[0] = 0xfffffffffffffffeULL;
  s_sub_cmp.value_ptr()[1] = 0x0105ULL;
  s_sub_cmp.toggle_sign();
  s_sub_cmp.normalize();

  s_mult_cmp.value_ptr()[0] = 0x1ULL;
  s_mult_cmp.value_ptr()[1] = 0xfffffffffffffefaULL;
  s_mult_cmp.value_ptr()[2] = 0x05ffULL;
  s_mult_cmp.toggle_sign();
  s_mult_cmp.normalize();

  s_div_cmp.value_ptr()[0] = 0x2aULL;
  s_div_cmp.toggle_sign();
  s_div_cmp.normalize();

  r.zero_num();
  if (!big_add(n1, n2, r)) {
    printf("big_add fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    n1.print(); printf(" + ");
    n2.print(); printf(" = ");
    r.print(); printf("\n");
  }
  if (big_compare(r, s_add_cmp) != 0) {
    printf("bad compare 6\n");
    return false;
  }

  r.zero_num();
  if (!big_sub(n1, n2, r)) {
    printf("big_sub fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    n1.print(); printf(" - ");
    n2.print(); printf(" = ");
    r.print(); printf("\n");
  }
  if (big_compare(r, s_sub_cmp) != 0) {
    printf("bad compare 7\n");
    return false;
  }

  r.zero_num();
  if (!big_mult(n1, n2, r)) {
    printf("big_mult fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    n1.print(); printf(" * ");
    n2.print(); printf(" = ");
    r.print(); printf("\n");
  }
  if (big_compare(r, s_mult_cmp) != 0) {
    printf("bad compare 8\n");
    return false;
  }

  r.zero_num();
  if (!big_div(n1, n2, r)) {
    printf("big_div fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    n1.print(); printf(" / ");
    n2.print(); printf(" = ");
    r.print(); printf("\n");
  }
  if (big_compare(r, s_div_cmp) != 0) {
    printf("bad compare 9\n");
    return false;
  }

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

  m.value_ptr()[0] = 0ULL;
  m.value_ptr()[1] = 0x4ULL;
  a.value_ptr()[0] = 0x08f0ULL;
  a.value_ptr()[1] = 0x8000ULL;
  a.normalize();
  m. normalize();
  if (FLAGS_print_all)  {
    printf("Before mod: ");
    a.print(); printf(" (mod ");
    m.print(); printf(")\n");
  }
  if (!big_mod_normalize(a, m))
    return false;
  if (FLAGS_print_all)  {
    printf("After mod : ");
    a.print(); printf(" (mod ");
    m.print(); printf(")\n");
  }
  big_num norm_cmp(2, 0x08f0);
  if (big_compare(a, norm_cmp) != 0)
     return false;
  a.value_ptr()[0] = 93;
  b.value_ptr()[0] = 37;
  a.normalize();
  b.normalize();
  if (!big_extended_gcd(a, b, x, y, g))
    return false;
  if (FLAGS_print_all)  {
    printf("(");
    a.print();
    printf(") (");
    x.print();
    printf(") + (");
    b.print();
    printf(") (");
    y.print();
    printf(") = (");
    g.print();
    printf(")\n");
  }

  a.zero_num();
  a.value_ptr()[0] = 93;
  m.zero_num();
  m.value_ptr()[0] = 37;
  a.normalize();
  if (!big_mod(a, m, r))
    return false;
  if (FLAGS_print_all)  {
    printf("(");
    a.print();
    printf(") (mod ");
    m.print();
    printf(") = (");
    r.print();
    printf(")\n");
  }
  if (r.value_ptr()[0] != 0x13)
    return false;

  b.zero_num();
  b.value_ptr()[0] = 93;
  a.normalize();
  b.normalize();
  r.zero_num();
  if (!big_mod_add(a, b, m, r))
    return false;
  if (FLAGS_print_all)  {
    printf("(");
    a.print();
    printf(") + (");
    b.print();
    printf(")  (mod ");
    m.print();
    printf(") = (");
    r.print();
    printf(")\n");
  }
  if (r.value_ptr()[0] != 0x1)
    return false;

  r.zero_num();
  if (!big_mod_neg(a, m, r))
    return false;
  if (FLAGS_print_all)  {
    printf("-(");
    a.print();
    printf(")  (mod ");
    m.print();
    printf(") = (");
    r.print();
    printf(")\n");
  }
  if (r.value_ptr()[0] != 0x12)
    return false;

  r.zero_num();
  if (!big_mod_mult(a, b, m, r))
    return false;
  if (FLAGS_print_all)  {
    printf("(");
    a.print();
    printf(") * (");
    b.print();
    printf(")  (mod ");
    m.print();
    printf(") = (");
    r.print();
    printf(")\n");
  }
  if (r.value_ptr()[0] != 0x1c)
    return false;

  r.zero_num();
  if (!big_mod_square(a, m, r))
    return false;
  if (FLAGS_print_all)  {
    printf("(");
    a.print();
    printf(") ** 2 (");
    m.print();
    printf(")  (mod ");
    printf(") = (");
    r.print();
    printf(")\n");
  }
  if (r.value_ptr()[0] != 0x1c)
    return false;

  r.zero_num();
  if (!big_mod_div(a, b, m, r))
    return false;
  if (FLAGS_print_all)  {
    printf("(");
    a.print();
    printf(") / (");
    b.print();
    printf(")  (mod ");
    m.print();
    printf(") = (");
    r.print();
    printf(")\n");
  }
  if (r.value_ptr()[0] != 0x1)
    return false;

  r.zero_num();
  e.value_ptr()[0] = 4ULL;
  e.normalize();
  if (!big_mod_exp(a, e, m, r))
    return false;
  if (FLAGS_print_all)  {
    printf("(");
    a.print();
    printf(") ** (");
    e.print();
    printf(")  (mod ");
    m.print();
    printf(") = (");
    r.print();
    printf(")\n");
  }
  if (r.value_ptr()[0] != 0x7)
    return false;

  r.zero_num();
  x.zero_num();
  c1.value_ptr()[0] = 37;
  c2.value_ptr()[0] = 93;
  a.value_ptr()[0] = 140 % 37;
  b.value_ptr()[0] = 140 % 93;
  c1.normalize();
  c2.normalize();
  a.normalize();
  b.normalize();
  if (!big_crt(a, b, c1, c2, r))
    return false;
  if (!big_mult(c1, c2, x))
    return false;
  if (FLAGS_print_all)  {
    printf("x = (");
    a.print();
    printf(")  (mod ");
    c1.print();
    printf(")\n");
    printf("x = (");
    b.print();
    printf(")  (mod ");
    c2.print();
    printf(")\n");
    printf("x = (");
    r.print();
    printf(") (mod ");
    x.print();
    printf(")\n");
  }
  if (r.value_ptr()[0] != 140)
    return false;

  p.value_ptr()[0]= 3583;
  p.normalize();
  n.zero_num();
  n.value_ptr()[0]= 4;
  n.normalize();
  if (FLAGS_print_all)  {
    printf("(");
    n.print();
  }
  if (big_mod_is_square(n, p)) {
    if (FLAGS_print_all)  {
      printf(") is a square (mod ");
    }
  }  else {
    if (FLAGS_print_all)  {
      printf(") is NOT a square (mod ");
    }
  }
  if (FLAGS_print_all)  {
    p.print();
    printf(")\n");
  }

  r.zero_num();
  p.normalize();
  n.normalize();
  if (!big_mod_square_root(n, p, r))
    return false;
  if (FLAGS_print_all)  {
    printf("sqrt (");
    n.print();
    printf(")  (mod ");
    p.print();
    printf(") = ");
    r.print();
    printf(")\n");
  }
  if (r.value_ptr()[0] != 2)
    return false;

  s.zero_num();
  if (!big_mod_tonelli_shanks(n, p, s))
    return false;
  if (FLAGS_print_all)  {
    printf("tonelli-shanks sqrt (");
    n.print();
    printf(")  (mod ");
    p.print();
    printf(") = ");
    s.print();
    printf(")\n");
  }
  if (s.value_ptr()[0] != 2)
    return false;

  s.zero_num();
  n.value_ptr()[0]= 16;
  if (!big_mod_tonelli_shanks(n, p, s))
    return false;
  if (FLAGS_print_all)  {
    printf("tonelli-shanks sqrt (");
    n.print();
    printf(")  (mod ");
    p.print();
    printf(") = ");
    s.print();
    printf(")\n");
  }
  if (s.value_ptr()[0] != 4)
    return false;

  r.zero_num();
  if (!big_mod_inv(n, p, r))
    return false;
  if (FLAGS_print_all)  {
    printf("(");
    n.print();
    printf(") ^ -1  (mod ");
    p.print();
    printf(") = (");
    r.print();
    printf(")\n");
  }
  if (r.value_ptr()[0] != 224)
    return false;

  int num_bits = 128;
  big_num** random_a = new big_num*[20];
  for (int j = 0; j < 20; j++) {
    random_a[j] = new big_num(5);
    if (crypto_get_random_bytes((num_bits + NBITSINBYTE - 1)/ NBITSINBYTE, (byte*)random_a[j]->value_ptr()) < 0)
      return false;
    random_a[j]->normalize();
  }
  if (big_miller_rabin(n, random_a, 20)) {
    if (FLAGS_print_all)
      printf("miller rabin returns true\n");
  } else {
    if (FLAGS_print_all)
      printf("miller rabin returns false\n");
  }

  p.zero_num();
  if (!big_gen_prime(p, num_bits, 250)) {
    printf("big_gen_prime fails\n");
    return false;
  }
  if (FLAGS_print_all)  {
    printf("proposed prime: (");
    p.print();
    printf(")\n");
  }
  if (!big_high_bit(p))
    return false;
  if (!big_is_prime(p)) {
    printf("big_is_prime fails\n");
    return false;
  }

  return true;
}

bool big_mont_test1() {

  int r = 13;
  big_num m(10, 2773ULL);
  big_num a(10, 20ULL);
  big_num b(10, 30ULL);
  big_num m_prime(10);
  big_num mont_a(10);
  big_num mont_b(10);
  big_num mont_c(10);
  big_num c(10);

  a.normalize();
  b.normalize();
  m.normalize();

  // for R = 2^r
  if (!big_make_mont(a, r, m, mont_a))
    return false;
  if (FLAGS_print_all) {
    printf("r: %d, %ld %ld = %ld\n", r, a.value_[0], 
        (1ULL<<13), mont_a.value_[0]);
  }
  if (mont_a.value_[0] != 233)
    return false;
  if (!big_make_mont(b, r, m, mont_b))
    return false;
  if (FLAGS_print_all) {
    printf("r: %d, %ld %ld = %ld\n", r, b.value_[0], 
        (1ULL<<13), mont_b.value_[0]);
  }
  if (mont_b.value_[0] != 1736)
    return false;
  
  // m_prime = -1/m (mod R)
  if (!big_mont_params(m, r, m_prime))
    return false;
  if (FLAGS_print_all) {
    printf("r: %d, m: %ld, m_prime: %ld\n", r, m.value_[0], m_prime.value_[0]);
  }
  if (m_prime.value_[0] != 387)
    return false;

  if (!big_mont_reduce(mont_a, r, m, m_prime, c))
    return false;
  if (FLAGS_print_all) {
    printf("r: %d, m: %ld, a: %ld, reduced: %ld\n", r, m.value_[0],
      mont_a.value_[0], c.value_[0]);
  }
  if (c.value_[0] != a.value_[0])
    return false;

  c.zero_num();
  // Compute mont_a = mont_a mont_b R^(-1) (mod p)
  if (!big_mont_mult(mont_a, mont_b, m, r, m_prime, c))
    return false;
  if (FLAGS_print_all) {
    printf("a: %ld, b: %ld, abR^(-1): %ld\n", mont_a.value_[0],
        mont_b.value_[0], c.value_[0]);
  }
  if (c.value_[0] != 1444)
    return false;

#if 0
  if (!big_mont_exp(b, e, r, m, m_prime, out))
    return false;
#endif
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
TEST(big_num, basic_num_test1) {
  EXPECT_TRUE(basic_big_num_test1());
}
TEST(big_num, basic_arith_test1) {
  EXPECT_TRUE(basic_arith_test1());
}
TEST(big_num, basic_number_theory_test1) {
  EXPECT_TRUE(basic_number_theory_test1());
}
TEST(big_num, montgomery) {
  EXPECT_TRUE(big_mont_test1());
}

int main(int an, char** av) {

#if defined(X64)
  uint64_t cycles_per_second = calibrate_rdtsc();
  printf("This computer has %llu cycles per second\n", cycles_per_second);
#endif

  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!init_crypto()) {
    printf("Can't init_crypto\n");
    return 1;
  }

  int result = RUN_ALL_TESTS();

  close_crypto();
  return result;
}

