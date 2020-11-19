// Copyright 2014-2020, John Manferdelli, All Rights Reserved.
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
// File: test_arm_big_num.cc

#include <crypto_support.h>
#include <arm64_digit_arith.h>
#include <big_num.h>
#include <big_num_functions.h>

#if 1
// remove this when we compile cryptsupport
void reverse_bytes_in_place(int size, byte* b) {
  byte t;

  for (int i = 0; i < (size / 2); i++) {
    t = b[size - 1 - i];
    b[size - 1 - i] = b[i];
    b[i] = t;
  }
}
#endif

void print_compare_val(int k) {
  switch(k) {
  case 1:
    printf(" > ");
    break;
  case 0:
    printf(" = ");
    break;
  case -1:
    printf(" < ");
    break;
  }
}

bool test_add_step() {
  uint64_t a, b, carry_in, carry_out, carry, result;

  carry_in = 0ULL;
  carry = carry_in << 29;

  result = 0;
  a = 0xffffffffffffffffULL;
  b = 1;
  u64_add_step(a, b, &result, &carry);
  carry_out = (carry != 0);
  printf("u64_add_step: ");
  printf("%lx + %lx  + %lx = %lx, carry_out: %lx\n", a, b, carry_in, result, carry_out);

  result = 0;
  a = 0xffffffffffffffffULL;
  b = 2;
  u64_add_step(a, b, &result, &carry);
  carry_out = (carry != 0);
  printf("u64_add_step: ");
  printf("%lx + %lx  + %lx = %lx, carry_out: %lx\n", a, b, carry_in, result, carry_out);

  carry_in = 1;
  result = 0;
  carry = carry_in << 29ULL;
  result = 0;
  a = 0xffffffffffffffffULL;
  b = 2;
  u64_add_step(a, b, &result, &carry);
  carry_out = (carry != 0);
  printf("u64_add_step: ");
  printf("%lx + %lx  + %lx = %lx, carry_out: %lx\n", a, b, carry_in, result, carry_out);

  result = 0;
  a = 0xffffffffffffffffULL;
  b =  0xffULL;
  u64_add_step(a, b, &result, &carry);
  carry_out = (carry != 0);
  printf("u64_add_step: ");
  printf("%lx + %lx  + %lx = %lx, carry_out: %lx\n", a, b, carry_in, result, carry_out);

  return true;
}

bool test_mult_step() {

  uint64_t a, b;
  uint64_t hi_digit = 0ULL;
  uint64_t lo_digit = 0ULL;

  a = 0xffffffffffffffffULL;
  b = 0x100;
  printf("u64_mult_step: ");
  u64_mult_step(a, b, &lo_digit, &hi_digit);
  printf("%016llx *  %016llx =  %016lx:%016lx\n", a, b, hi_digit, lo_digit);
  return true;
}

bool test_add_with_carry_step() {
  // u64_add_with_carry_step(a, b, carry_in, result, carry_out)
  return true;
}

bool test_sub_with_borrow_step() {
  uint64_t a = 5ULL;
  uint64_t b = 3ULL;
  uint64_t borrow_in = 1ULL;
  uint64_t borrow_out;
  uint64_t result = 0ULL;
  u64_sub_with_borrow_step(a, b, borrow_in, &result, &borrow_out);
  printf("%016llx -  %016llx borrow: %016llx=  %016lx, borrow_out: %016lx\n",
         a, b, borrow_in, result, borrow_out);

  a = 0ULL;
  b = 1ULL;
  borrow_in = 1ULL;
  borrow_out = 0ULL;
  result = 0ULL;
  u64_sub_with_borrow_step(a, b, borrow_in, &result, &borrow_out);
  printf("%016llx -  %016llx borrow: %016llx=  %016lx, borrow_out: %016lx\n",
         a, b, borrow_in, result, borrow_out);
  return true;
}

bool test_mult_with_carry_step() {
  uint64_t a = 0xffffffffffffffffULL;
  uint64_t b = 0x100ULL;
  uint64_t carry1= 0xffULL;
  uint64_t carry2= 0xffULL;
  uint64_t lo_digit = 0ULL;
  uint64_t hi_digit = 0ULL;

  u64_mult_with_carry_step(a, b, carry1, carry2, &lo_digit, &hi_digit);
  printf("%016llx * %016llx + %016llx + %016llx = %016llx::%016llx\n", a, b, carry1, carry2,
          hi_digit, lo_digit);
  return true;
}

bool check_div(uint64_t a, uint64_t b, uint64_t c, uint64_t q, uint64_t r) {
  uint64_t lo = 0ULL;
  uint64_t hi = 0ULL;

  u64_mult_step(c, q, &lo, &hi);
  uint64_t c_in = 0ULL;
  uint64_t c_out = 0ULL;
  uint64_t a1= 0ULL;
  uint64_t a2= 0ULL;
  u64_add_with_carry_step(lo, r, c_in, &a2, &c_out);
  c_in = c_out; c_out = 0ULL;
  u64_add_with_carry_step(hi, 0ULL, c_in, &a1, &c_out);
  if (a1 != a || a2 != b)
    return false;
  return true;
}

bool test_div_step() {
  uint64_t a = 0xffff;
  uint64_t b = 0xffffffffffffffffULL;
  uint64_t c = 0xfffffULL;
  uint64_t q = 0ULL;
  uint64_t r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016llx : %016llx / %016llx 016llx = %016llx, rem: %016llx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 0x2;
  b = 0ULL;
  c = 0xffffffffffffffffULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016llx : %016llx / %016llx 016llx = %016llx, rem: %016llx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 0ULL;
  b = 0xffffffffffffffffULL;
  c = 0xffffffffffffffULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016llx : %016llx / %016llx 016llx = %016llx, rem: %016llx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 1ULL;
  b = 0xffffffffffffffffULL;
  c = 0xfULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016llx : %016llx / %016llx 016llx = %016llx, rem: %016llx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  return true;
}

bool test_multi_add() {
  int size_op1 = 3;
  uint64_t op1[3] = {
    0xfffffffffffffffdULL,
    0xffffffffffffffffULL,
    0x0ULL
  };
  int size_op2 = 2;
  uint64_t op2[2] = {
    0x06ULL,
    0x0101010101010101
  };
  uint64_t result[4];
  int i = digit_array_add(size_op1, op1, size_op2, op2, 4, result);
  digit_array_print(size_op1, op1);
  printf(" + ");
  digit_array_print(size_op2, op2);
  printf(" = ");
  digit_array_print(i, result);
  printf("\n");

  return true;
}

bool test_multi_sub() {
  int size_op1 = 3;
  uint64_t op1[3] = {
    0xfffffffffffffff0ULL,
    0xffffffffffffffffULL,
    0x0ULL
  };
  int size_op2 = 2;
  uint64_t op2[2] = {
    0x06ULL,
    0x0101010101010101
  };
  uint64_t result[4];
  int i = digit_array_sub(size_op1, op1, size_op2, op2, 4, result);
  digit_array_print(size_op1, op1);
  printf(" - ");
  digit_array_print(size_op2, op2);
  printf(" = ");
  digit_array_print(i, result);
  printf("\n");
  return true;
}

bool test_multi_mult() {
  int size_op1 = 3;
  uint64_t op1[3] = {
    0xfffffffffffffffdULL,
    0xffffffffffffffffULL,
    0x0ULL
  };
  int size_op2 = 2;
  uint64_t op2[2] = {
    0x06ULL,
    0x0101010101010101
  };
  uint64_t result[8];
  int i = digit_array_mult(size_op1, op1, size_op2, op2, 4, result);
  digit_array_print(size_op1, op1);
  printf(" * ");
  digit_array_print(size_op2, op2);
  printf(" = ");
  digit_array_print(i, result);
  printf("\n");
  return true;
}

bool test_short_div() {
  uint64_t op1 = 0x7777;
  int size_op2 = 2;
  uint64_t op2[2] = {
    0x77777ULL,
    0x7771ULL,
  };
  uint64_t opq[4];
  uint64_t r = 0ULL;
  digit_array_zero_num(4, opq);
  int size_q = 4;
  if (!digit_array_short_division_algorithm(size_op2, op2, op1, &size_q, opq, &r))
    return false;
  digit_array_print(size_op2, op2);
  printf(" / %0llx = ", op1);
  digit_array_print(size_q, opq);
  printf(", rem: %llx\n", r);
  return true;
}

bool test_estimate_quotient() {
  uint64_t a1 =0x2ULL;;
  uint64_t a2= 0x0101010102020202;
  uint64_t a3= 0x0ULL;
  uint64_t b1= 0x00ffffffffffffff;
  uint64_t b2= 0ULL;
  uint64_t est;
  // estimate_quotient(a1, a2, a3, b1, b2, &est);
  return true;
}

bool test_multi_euclid() {
  int size_op1 = 3;
  uint64_t op1[3] = {
  };
  int size_op2 = 2;
  uint64_t op2[2] = {
  };
  uint64_t result[4];
  return true;
}

int main(int an, char** av) {

  printf("\ntest_add_step\n");
  if (test_add_step()) {
    printf("test_add_step succeeds\n");
  } else {
    printf("test_add_step fails\n");
  }

  printf("\ntest_mult_step\n");
  if (test_mult_step()) {
    printf("test_mult_step succeeds\n");
  } else {
    printf("test_mult_step fails\n");
  }

  printf("\ntest_mult_with_carry_step\n");
  if (test_mult_with_carry_step()) {
    printf("test_mult_with_carry_step succeeds\n");
  } else {
    printf("test_mult_with_carry_step fails\n");
  }

  printf("\ntest_add_with_carry_step\n");
  if (test_add_with_carry_step()) {
    printf("test_add_with_carry_step succeeds\n");
  } else {
    printf("test_add_with_carry_step fails\n");
  }

  printf("\ntest_sub_with_borrow_step\n");
  if (test_sub_with_borrow_step()) {
    printf("test_sub_with_borrow_step succeeds\n");
  } else {
    printf("test_sub_with_borrow_step fails\n");
  }

  printf("\ntest_div_step\n");
  if (test_div_step()) {
    printf("test_div_step succeeds\n");
  } else {
    printf("test_div_step fails\n");
  }

  printf("\ntest_multi_add\n");
  if (test_multi_add()) {
    printf("test_multi_add succeeds\n");
  } else {
    printf("test_multi_add fails\n");
  }

  printf("\ntest_multi_sub\n");
  if (test_multi_sub()) {
    printf("test_multi_sub succeeds\n");
  } else {
    printf("test_multi_sub fails\n");
  }

  printf("\ntest_multi_mult\n");
  if (test_multi_mult()) {
    printf("test_multi_mult succeeds\n");
  } else {
    printf("test_multi_mult fails\n");
  }

  printf("\ntest_short_div\n");
  if (test_short_div()) {
    printf("test_short_div succeeds\n");
  } else {
    printf("test_short_div fails\n");
  }

  printf("\ntest_estimate_quotient\n");
  if (test_estimate_quotient()) {
    printf("test_estimate_quotient succeeds\n");
  } else {
    printf("test_estimate_quotient fails\n");
  }

  printf("\ntest_multi_euclid\n");
  if (test_multi_euclid()) {
    printf("test_multi_euclid succeeds\n");
  } else {
    printf("test_multi_euclid fails\n");
  }

  printf("\ndone\n");
  return 0;
}

