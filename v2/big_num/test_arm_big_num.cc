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
  if (result != 0ULL || carry_out != 1)
    return false;

  result = 0;
  a = 0xffffffffffffffffULL;
  b = 2;
  u64_add_step(a, b, &result, &carry);
  carry_out = (carry != 0);
  printf("u64_add_step: ");
  printf("%lx + %lx  + %lx = %lx, carry_out: %lx\n", a, b, carry_in, result, carry_out);
  if (result != 1ULL || carry_out != 1)
    return false;

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
  if (result != 2ULL || carry_out != 1)
    return false;

  result = 0;
  a = 0xffffffffffffffffULL;
  b =  0xffULL;
  u64_add_step(a, b, &result, &carry);
  carry_out = (carry != 0);
  printf("u64_add_step: ");
  printf("%lx + %lx  + %lx = %lx, carry_out: %lx\n", a, b, carry_in, result, carry_out);
  if (result != 0xfeULL || carry_out != 1)
    return false;

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
  printf("%016lx *  %016lx =  %016lx:%016lx\n", a, b, hi_digit, lo_digit);
  if (hi_digit != 0xffULL || lo_digit != 0xffffffffffffff00)
    return false;
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
  printf("%016lx -  %016lx borrow: %016lx=  %016lx, borrow_out: %016lx\n",
         a, b, borrow_in, result, borrow_out);
  if (result != 0x2ULL || borrow_out != 1)
    return false;

  a = 0ULL;
  b = 1ULL;
  borrow_in = 1ULL;
  borrow_out = 0ULL;
  result = 0ULL;
  u64_sub_with_borrow_step(a, b, borrow_in, &result, &borrow_out);
  printf("%016lx -  %016lx borrow: %016lx=  %016lx, borrow_out: %016lx\n",
         a, b, borrow_in, result, borrow_out);
  if (result != 0xffffffffffffffffULL || borrow_out != 0)
    return false;
  return true;
}

bool test_mult_with_carry_step() {
  uint64_t a = 0xffffffffffffffffULL;
  uint64_t b = 0x100ULL;
  uint64_t carry1= 0xffULL;
  uint64_t carry2= 0xffULL;
  uint64_t lo_digit = 0ULL;
  uint64_t hi_digit = 0ULL;

  u64_product_step(a, b, carry1, carry2, &lo_digit, &hi_digit);
  printf("%016lx * %016lx + %016lx + %016lx = %016lx::%016lx\n", a, b, carry1, carry2,
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
  if (a1 != a || a2 != b) {
    printf("%016lx:%016lx = %016lx * %016lx + %016lx (%016lx:%016lx)\n", a,b,c,q,r,a1,a2);
    return false;
  }
  return true;
}

bool test_div_step() {
  uint64_t a = 0xffff;
  uint64_t b = 0xffffffffffffffffULL;
  uint64_t c = 0xfffffULL;
  uint64_t q = 0ULL;
  uint64_t r = 0ULL;

  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 0x2;
  b = 0ULL;
  c = 0xffffffffffffffffULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 0ULL;
  b = 0xffffffffffffffffULL;
  c = 0xffffffffffffffULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 1ULL;
  b = 0xffffffffffffffffULL;
  c = 0xfULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 0x1fULL;
  b = 0xffffffffffffffffULL;
  c = 0xbfffffffffffffffULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 0x00fffffffffffe0cULL;
  b = 0x0000000000f42301ULL;
  c = 0xffffffffffff0700ULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 0x901d0e94f9df6f26ULL;
  b = 0xd55da1e53722fc58ULL;
  c = 0xffffffff00000001ULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  // div step: a: 915827bab37e4902, b: 88aa2961e43416b5, c: ffffffff00000001

  a = 0x915827bab37e4902ULL;
  b = 0x88aa2961e43416b5ULL;
  c = 0xffffffff00000001ULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 0x96f83925527638b1ULL;
  b = 0xeebc1e519b105cb0ULL;
  c = 0xffffffff00000001ULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 0xf9b8d7644fba7c42ULL;
  b = 0x0667eedfe773a90dULL;
  c = 0xffffffff00000001ULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 0x7c42ULL;
  b = 0x0667eedfe773a90dULL;
  c = 0xfffffULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
  if (!check_div(a, b, c, q, r))
    return false;

  a = 0ULL;
  b = 0x2cccebb86e0def74ULL;
  c = 0xffffffff00000001ULL;
  q = 0ULL;
  r = 0ULL;
  u64_div_step(a, b, c, &q, &r);
  printf("%016lx : %016lx / %016lx = %016lx, rem: %016lx\n", a, b, c, q, r);
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

  uint64_t ans1[3] = {
    0x0000000000000003ULL,
    0x0101010101010101ULL,
    0x0000000000000001ULL,
  };
    
  int i = digit_array_add(size_op1, op1, size_op2, op2, 4, result);
  digit_array_print(size_op1, op1);
  printf(" + ");
  digit_array_print(size_op2, op2);
  printf(" = ");
  digit_array_print(i, result);
  printf("\n");
  if (digit_array_compare(i, result, 3, ans1) != 0)
    return false;

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
  uint64_t ans1[2] = {
    0xffffffffffffffeaULL,
    0xfefefefefefefefeULL,
  };
  uint64_t ans2[1] = {
    0xffffffffffff0003ULL
  };


  digit_array_zero_num(4, result);
  int i = digit_array_sub(size_op1, op1, size_op2, op2, 4, result);
  digit_array_print(size_op1, op1);
  printf(" - ");
  digit_array_print(size_op2, op2);
  printf(" = ");
  digit_array_print(i, result);
  printf("\n");
  digit_array_print(2, ans1);
  printf("\n");
  if (digit_array_compare(i, result, 2, ans1) != 0)
    return false;

  op1[0] = 0x2ULL;
  op1[1] = 0x2ULL;
  op1[2] = 0x0ULL;
  op2[1]= 1ULL;
  op2[0]= 0xffffULL;
  digit_array_zero_num(4, result);
  i = digit_array_sub(size_op1, op1, size_op2, op2, 4, result);
  digit_array_print(size_op1, op1);
  printf(" - ");
  digit_array_print(size_op2, op2);
  printf(" = ");
  digit_array_print(i, result);
  printf("\n");
  if (digit_array_compare(i, result, 1, ans2) != 0)
    return false;
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
  printf(" / %0lx = ", op1);
  digit_array_print(size_q, opq);
  printf(", rem: %lx\n", r);

  uint64_t result[3];
  digit_array_zero_num(3, result);
  int i = digit_array_mult(1, &op1, size_q, opq, 3, result);
  digit_array_print(size_q, opq);
  printf(" * %lx = ", op1);
  digit_array_print(i, result);
  printf("\n");

  op2[1]= 1ULL;
  op2[0]= 0ULL;
  op1 = 10ULL;
  digit_array_zero_num(4, opq);
  r = 0ULL;
  size_q = 4;
  if (!digit_array_short_division_algorithm(size_op2, op2, op1, &size_q, opq, &r))
    return false;
  digit_array_print(size_op2, op2);
  printf(" / %0ld = ", op1);
  digit_array_print(size_q, opq);
  printf(", rem: %lx\n", r);

  return true;
}

bool test_estimate_quotient() {
  uint64_t a1 =0x2ULL;;
  uint64_t a2= 0x0101010102020202;
  uint64_t a3= 0x0ULL;
  uint64_t b1= 0x00ffffffffffffff;
  uint64_t b2= 0ULL;
  uint64_t est = 0ULL;
  estimate_quotient(a1, a2, a3, b1, b2, &est);
  printf("%lx:%lx:%lx/:%lx:%lx, est is %lx\n", a1, a2, a3, b1, b2, est);
  uint64_t hi = 0ULL;
  uint64_t lo = 0ULL;
  u64_mult_step(b1, est, &lo, &hi);
  if (est != 0x201)
    return false;
  
  return true;
}

bool test_multi_euclid() {
  int size_op1 = 3;
  uint64_t op1[3] = {
    0x0ULL,
    0x22ULL,
    0x7777ULL,
  };
  int size_op2 = 2;
  uint64_t op2[2] = {
    0x877777,
    0x0ULL,
  };
  int size_q = 6;
  int size_r = 3;
  uint64_t result[6];
  uint64_t rem[4];

  digit_array_zero_num(6, result);
  digit_array_zero_num(4, rem);
  if (!digit_array_division_algorithm(size_op1, op1, size_op2, op2,
        &size_q, result, &size_r, rem))
    return false;
  digit_array_print(size_op1, op1);
  printf(" / ");
  digit_array_print(size_op2, op2);
  printf(" = ");
  digit_array_print(size_q, result);
  printf(", rem: ");
  digit_array_print(size_r, rem);
  printf("\n");

  int size_r2 = 6;
  uint64_t result2[6];
  int size_r3 = 6;
  uint64_t result3[6];
  digit_array_zero_num(size_r2, result2);
  digit_array_zero_num(size_r3, result3);
  size_r2 = digit_array_mult(size_q, result, size_op2, op2, size_r2, result2);
  size_r3 = digit_array_add(size_r2, result2, size_r, rem, size_r3, result3);
  digit_array_print(size_op2, op2);
  printf(" * ");
  digit_array_print(size_q, result);
  printf(" + ");
  digit_array_print(size_r, rem);
  printf(" = ");
  digit_array_print(size_r3, result3);
  printf("\n");
  if (digit_array_compare(size_op1, op1, size_r3, result3) != 0)
    return false;

  int size_op3 =10;
  uint64_t op3[size_op3] = {
    0x30edd460c607afe4ULL,
    0x1ffd1a5bd36cd015ULL,
    0xc89de54fe3a13ecaULL,
    0xb8d5b1119b64b5c2ULL,
    0x70387d127a032f22ULL,
    0xd92ade46207ebdf8ULL,
    0xd4d2435551cd0b7cULL,
    0x2cccebb86e0def74ULL,
    0x0ULL,
    0x0ULL,
  };
  int size_op4 = 5;
  uint64_t op4[size_op4] = {
    0xffffffffffffffffULL,
    0x00000000ffffffffULL,
    0x0ULL,
    0xffffffff00000001ULL,
    0x0ULL,
  };
  int size_op5 = 10;
  uint64_t op5[size_op5];
  int size_op6 = 10;
  uint64_t op6[size_op6];
  int size_op7 = 10;
  uint64_t op7[size_op7];
  int size_op8 = 10;
  uint64_t op8[size_op8];

  digit_array_zero_num(size_op5, op5);
  digit_array_zero_num(size_op6, op6);
  digit_array_zero_num(size_op7, op7);
  digit_array_zero_num(size_op8, op8);

  digit_array_print(size_op3, op3);
  printf(" / ");
  digit_array_print(size_op4, op4);
  printf("\n");
  size_q = size_op5;
  size_r = size_op6;
  if (!digit_array_division_algorithm(size_op3, op3, size_op4, op4,
        &size_q, op5, &size_r, op6))
    return false;
  digit_array_print(size_op3, op3);
  printf(" / ");
  digit_array_print(size_op4, op4);
  printf(" = ");
  digit_array_print(size_q, op5);
  printf(", rem: ");
  digit_array_print(size_r, op6);
  printf("\n");

  int size_s = digit_array_mult(size_q, op5, size_op4, op4, size_op7, op7);
  int size_u = digit_array_add(size_s, op7, size_r, op6, size_op8, op8);
  digit_array_print(size_q, op5);
  printf(" * ");
  digit_array_print(size_op4, op4);
  printf(" + ");
  digit_array_print(size_r, op6);
  printf(" = ");
  digit_array_print(size_u, op8);
  printf("\n");
  if (digit_array_compare(size_op3, op3, size_op8, op8) != 0)
    return false;

  return true;
}

bool test_add_to() {
  int size_op1 = 6;
  uint64_t op1[6] = {
    0xffffffffffffffffULL,
  };
  int size_op2 = 2;
  uint64_t op2[2] = {
    0xffffffffffffffffULL,
  };

  int real_size_op1 = digit_array_real_size(size_op1, op1);
  int real_size_op2 = digit_array_real_size(size_op2, op2);

  printf("op1: "); digit_array_print(real_size_op1, op1); printf("\n");
  printf("op2: "); digit_array_print(real_size_op2, op2); printf("\n");

  int i = digit_array_add_to(size_op1, real_size_op1, op1, real_size_op2, op2);
  if (i < 0)
      return false;
  printf("add to (%d): ", i); digit_array_print(size_op1, op1); printf("\n");
  if (op1[0] != 0xfffffffffffffffeULL || op1[1] != 1ULL)
    return false;

  real_size_op1 = digit_array_real_size(size_op1, op1);
  i = digit_array_add_to(size_op1, real_size_op1, op1, real_size_op2, op2);
  if (i < 0)
      return false;
  printf("add to: "); digit_array_print(i, op1); printf("\n");
  if (op1[0] != 0xfffffffffffffffdULL || op1[1] != 2ULL)
    return false;

  real_size_op1 = digit_array_real_size(size_op1, op1);
  i = digit_array_add_to(size_op1, real_size_op1, op1, real_size_op2, op2);
  if (i < 0)
      return false;
  printf("add to: "); digit_array_print(i, op1); printf("\n");
  if (op1[0] != 0xfffffffffffffffcULL || op1[1] != 3ULL)
    return false;

  return true;
}

bool test_sub_from() {
  int size_op1 = 4;
  uint64_t op1[4] = {
    0xfffffffffffffffcULL,
    0x3ULL,
    0x0ULL,
    0x0ULL,
  };
  int size_op2 = 2;
  uint64_t op2[2] = {
    0xffffffffffffffffULL,
    0x0ULL,
  };

  int real_size_op1 = digit_array_real_size(size_op1, op1);
  int real_size_op2 = digit_array_real_size(size_op2, op2);

  printf("op1: "); digit_array_print(real_size_op1, op1); printf("\n");
  printf("op2: "); digit_array_print(real_size_op2, op2); printf("\n");

  int i = digit_array_sub_from(size_op1, real_size_op1, op1, real_size_op2, op2);
  if (i < 0)
      return false;
  printf("sub from (%d): ", i); digit_array_print(i, op1); printf("\n");
  if (op1[0] != 0xfffffffffffffffdULL || op1[1] != 2ULL)
     return false;

  real_size_op1 = digit_array_real_size(size_op1, op1);
  i = digit_array_sub_from(size_op1, real_size_op1, op1, real_size_op2, op2);
  if (i < 0)
      return false;
  printf("sub from (%d): ", i); digit_array_print(i, op1); printf("\n");
  if (op1[0] != 0xfffffffffffffffeULL || op1[1] != 1ULL)
     return false;

  real_size_op1 = digit_array_real_size(size_op1, op1);
  i = digit_array_sub_from(size_op1, real_size_op1, op1, real_size_op2, op2);
  if (i < 0)
      return false;
  printf("sub from (%d): ", i); digit_array_print(i, op1); printf("\n");
  if (op1[0] != 0xffffffffffffffffULL || op1[1] != 0ULL)
     return false;
  return true;
}

bool test_mult_by() {
  int size_op1 = 4;
  uint64_t op1[4] = {
    0xfffffffffffffffULL,
    0,
    0,
    0,
  };
  uint64_t op2 = 0x10;

  int real_size_op1 = digit_array_real_size(size_op1, op1);
  printf("op1: "); digit_array_print(real_size_op1, op1); printf("\n");
  printf("op2: %lx\n", op2);

  int i = digit_array_mult_by(size_op1, real_size_op1, op1, op2);
  if (i < 0)
      return false;
  printf("mult_by (%d): ", i); digit_array_print(i, op1); printf("\n");
  if (op1[0] != 0xfffffffffffffff0ULL || op1[1] != 0ULL)
      return false;

  real_size_op1 = digit_array_real_size(size_op1, op1);
  i = digit_array_mult_by(size_op1, real_size_op1, op1, op2);
  if (i < 0)
      return false;
  printf("mult_by (%d): ", i); digit_array_print(i, op1); printf("\n");
  if (op1[0] != 0xffffffffffffff00ULL || op1[1] != 0xfULL)
      return false;

  real_size_op1 = digit_array_real_size(size_op1, op1);
  i = digit_array_mult_by(size_op1, real_size_op1, op1, op2);
  if (i < 0)
      return false;
  printf("mult_by (%d): ", i); digit_array_print(i, op1); printf("\n");
  if (op1[0] != 0xfffffffffffff000ULL || op1[1] != 0xffULL)
      return false;

  return true;
}

bool test_convert_decimal() {
  string s1;
  string s2;
  int size_op1 = 4;
  uint64_t op1[4];
  digit_array_zero_num(size_op1, op1);

  s1 = "2048";
  if (!digit_convert_from_decimal(s1, size_op1, op1)) {
    printf ("Cannot convert %s from decimal\n", s1.c_str());
    return false;
  }
  printf("%s in binary: ", s1.c_str());
  digit_array_print(size_op1, op1); printf("\n");
  int real_size_op1 = digit_array_real_size(size_op1, op1);
  if (!digit_convert_to_decimal(real_size_op1, op1, &s2)) {
    printf ("Cannot convert to decimal\n");
    return false;
  }
  printf("Back to string: %s\n", s2.c_str());
  if (strcmp(s1.c_str(), s2.c_str()) != 0) {
    return false;
  }

  s1.clear();
  s2.clear();
  s1= "18446744073709551616";
  digit_array_zero_num(size_op1, op1);
  if (!digit_convert_from_decimal(s1, size_op1, op1)) {
    printf ("Cannot convert %s from decimal\n", s1.c_str());
    return false;
  }
  printf("%s in binary: ", s1.c_str());
  digit_array_print(size_op1, op1); printf("\n");
  real_size_op1 = digit_array_real_size(size_op1, op1);
  if (!digit_convert_to_decimal(real_size_op1, op1, &s2)) {
    printf ("Cannot convert to decimal\n");
    return false;
  }
  printf("Back to string: %s\n", s2.c_str());
  if (strcmp(s1.c_str(), s2.c_str()) != 0) {
    return false;
  }

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

  printf("\ntest_add_to\n");
  if (test_add_to()) {
    printf("test_add_to succeeds\n");
  } else {
    printf("test_add_to fails\n");
  }

  printf("\ntest_sub_from\n");
  if (test_sub_from()) {
    printf("test_sub_from succeeds\n");
  } else {
    printf("test_sub_from fails\n");
  }

  printf("\ntest_mult_by\n");
  if (test_mult_by()) {
    printf("test_mult_by succeeds\n");
  } else {
    printf("test_mult_by fails\n");
  }

  printf("\ntest_convert_decimal\n");
  if (test_convert_decimal()) {
    printf("test_convert_decimal succeeds\n");
  } else {
    printf("test_convert_decimal fails\n");
  }

  printf("\ndone\n");
  return 0;
}

