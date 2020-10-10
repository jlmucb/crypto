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
  uint64_t a, b, carry_in, carry, result;
  carry_in = 1;
  carry = carry_in;
  result = 0;
  a = 0xffffffffffffffffULL;
  b = 2;
  u64_add_step(a, b, &result, &carry);
  printf("\nu64_add_step: ");
  printf("%lx + %lx  + %lx = %lx, carry_out: %lx\n", a, b, carry_in, result, carry);

  return true;
}

bool test_mult_step() {

  uint64_t a, b;
  uint64_t r1, r2;
  a = 0xffffffffffffffffULL;
  b = 0x100;
  r1 = 0;
  r2 = 0;
  printf("\nu64_mult_step: ");
  u64_mult_step(a, b, &r1, &r2);
  printf("%lx *  %lx =  %016lx %016lx\n", a, b, r1, r2);
  return true;
}

bool test_add_with_carry_step() {
  // u64_add_with_carry_step(a, b, carry_in, result, carry_out)
  return true;
}

bool test_sub_with_borrow_step() {
  // u64_sub_with_borrow_step(a, b, borrow_in, result, borrow_out)
  return true;
}

bool test_mult_with_carry_step() {
  // u64_mult_with_carry_step(a, b, carry1, carry2, result, carry_out)
  return true;
}

bool test_estimate_quotient() {
  // estimate_quotient(a1, a2, a3, b1, b2, est)
  return true;
}

bool test_div_step() {
  // u64_div_step(uint64_t a, uint64_t b, uint64_t c, uint64_t* result, uint64_t* carry)
  return true;
}


int main(int an, char** av) {

#if 0
  extern void instruction_test(uint64_t a, uint64_t b, uint64_t* c, uint64_t* d);
  uint64_t a, b, c, d;

  a = 10;
  b = 0;
  c = 0;
  d = 0;

  instruction_test(a, b, &c, &d);
  printf("%lu --> %lu\n", a, d);
#else

  if (test_add_step()) {
    printf("test_add_step succeeds\n");
  } else {
    printf("test_add_step fails\n");
  }

  if (test_mult_step()) {
    printf("test_mult_step succeeds\n");
  } else {
    printf("test_mult_step fails\n");
  }

  if (test_add_with_carry_step()) {
    printf("test_add_with_carry_step succeeds\n");
  } else {
    printf("test_add_with_carry_step fails\n");
  }

  if (test_sub_with_borrow_step()) {
    printf("test_sub_with_borrow_step succeeds\n");
  } else {
    printf("test_sub_with_borrow_step fails\n");
  }

  if (test_mult_with_carry_step()) {
    printf("test_mult_with_carry_step succeeds\n");
  } else {
    printf("test_mult_with_carry_step fails\n");
  }

  if (test_estimate_quotient()) {
    printf("test_estimate_quotient succeeds\n");
  } else {
    printf("test_estimate_quotient fails\n");
  }

#endif

  printf("done\n");
  return 0;
}

