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
// File: arm64_digit_arith.cc

#include "crypto_support.h"
#include <arm64_digit_arith.h>


// digit_array_real_size --> digit_array_real_size
int digit_array_real_size(int size_a, uint64_t* a) {
  int n;

  for (n = (size_a - 1); n > 0; n--) {
    if (a[n] != 0ULL)
      break;
  }
  return n + 1;
}

void digit_array_print(int size_a, uint64_t* a) {
  int n = digit_array_real_size(size_a, a);

  for (int j = (n - 1); j >= 0; j--)
    printf("%016lx ", a[j]);
}

bool digit_array_is_zero(int size_a, uint64_t* a) {
  int i;

  for (i = 0; i < size_a; i++) {
    if (a[i] != 0ULL)
      return false;
  }
  return true;
}

void digit_array_zero_num(int size_a, uint64_t* a) {
  int i;

  for (i = 0; i < size_a; i++) a[i] = 0ULL;
}

// copy a-->b
bool digit_array_copy(int size_a, uint64_t* a, int size_b, uint64_t* b) {
  int i;

  if (size_b < size_a)
    return false;

  for (i = 0; i < size_a; i++) {
    b[i] = a[i];
  }
  for (; i < size_b; i++)
    b[i] = 0ULL;
  return true;
}

int digit_array_shift_up(int size_a, uint64_t* a, int shift, int size_r,
                         uint64_t* r) {
  int word_shift = shift / NBITSINUINT64;
  int partial_word_shift = shift - word_shift * NBITSINUINT64;
  int i;
  uint64_t x = 0ULL;
  int real_size_a = digit_array_real_size(size_a, a);

  if ((real_size_a + word_shift) >= size_r)
    return -1;
  digit_array_zero_num(size_r, r);
  for (i = (size_a - 1); i >= 0; i--) {
    x = a[i];
    if (partial_word_shift != 0)
      r[i + word_shift + 1] |= x >> (NBITSINUINT64 - partial_word_shift);
    r[i + word_shift] |= x << partial_word_shift;
  }
  return digit_array_real_size(size_r, r);
}

int digit_array_shift_down(int size_a, uint64_t* a, int shift, int size_r,
                        uint64_t* r) {
  int word_shift = shift / NBITSINUINT64;
  int partial_word_shift = shift - word_shift * NBITSINUINT64;
  int i;
  uint64_t x = 0ULL;
  int real_size_a = digit_array_real_size(size_a, a);

  if ((real_size_a - word_shift - 1) >= size_r)
    return -1;

  digit_array_zero_num(size_r, r);
  for (i = (size_a - word_shift - 1); i >= 0; i--) {
    x = a[i + word_shift];
    r[i] |= x >> partial_word_shift;
    if (i > 0 && partial_word_shift != 0)
      r[i - 1] |= x << (NBITSINUINT64 - partial_word_shift);
  }
  return digit_array_real_size(size_r, r);
}

// returns  1, if a>b
// returns  0, if a==b
// returns -1, if a<b
int digit_array_compare(int size_a, uint64_t* a, int size_b, uint64_t* b) {
  int i;
  int real_size_a = digit_array_real_size(size_a, a);
  int real_size_b = digit_array_real_size(size_b, b);

  if (real_size_a > real_size_b)
    return 1;
  if (real_size_a < real_size_b)
    return -1;
  for (i = (real_size_a - 1); i >= 0; i--) {
    if (a[i] > b[i])
      return 1;
    if (a[i] < b[i])
      return -1;
  }
  return 0;
}

int high_bit_in_digit(uint64_t a) {
  int i;

  for (i = (NBITSINUINT64 - 1); i >= 0; i--) {
    if (((1ULL << i) & a) != 0)
      return i + 1;
  }
  return 0;
}

int shift_to_top_bit(uint64_t a) {
  int i;

  for (i = 0; i < NBITSINUINT64; i++) {
    if (((a << i) & 0x8000000000000000) != 0)
      return i;
  }
  return NBITSINUINT64;
}

// Remove this later
// Don't forget its op  dst, src1, src2
void instruction_test(uint64_t a, uint64_t b, uint64_t* c, uint64_t* d) {
  *d = 0ULL;

  asm volatile (
    "mov    x9, %[d]\n\t"    // address of output
    "mov    x10, %[a]\n\t"   // a
    "mov    x11, 0\n\t"       // holds result
    ".1:\n\t"
    "add    x11, x11, x10\n\t"
    "subs   x10, x10, 1\n\t"
    "bne    .1\n\t"
    "str    x11, [x9]\n\t"
    :: [a] "r" (a), [b] "r" (b), [c] "r" (c), [d] "r" (d) :
      "memory", "x9", "x10", "x11");
}


// Don't forget its op  dst, src1, src2
// carry:result= a+b+carry_in
void u64_add_step(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry_in_out) {
  asm __volatile__ (
    "mov    x10, %[a]\n\t"                    // a
    "mov    x11, %[b]\n\t"                    // b
    "mov    x8, %[result]\n\t"                // &result
    "mov    X9, %[carry_in_out]\n\t"          // &carry_in_out
    "mrs    x13, NZCV\n\t"                    // get msr including NZCV conditions
    "mov    x14, 0xffffffff0fffffff\n\t"      // template for NZCV clear
    "and    x13, x13, x14\n\t"                // clear carry condition
    "ldr    x12, [x9]\n\t"                    // put new NZCV in x12
    "orr    x13, x13, x12\n\t"                // or in new carry condition
    "msr    NZCV, x13\n\t"                    // set NZCV
    "adcs   x12, x10, x11\n\t"                // add a, b
    "cset   x13, CS\n\t"                      // get carry flag
    "str    x12, [x8]\n\t"                    // store result in result
    "str    x13, [x9]\n\t"                    // store carry in carry
    :: [result] "r" (result), [carry_in_out] "r" (carry_in_out), [a] "r" (a), [b] "r" (b) : 
      "memory", "cc", "x8", "x9", "x10", "x11", "x12", "x13", "x14");
}

//  r1 is the high order digit, r2 is low order
//  r1:r2 = a * b
void u64_mult_step(uint64_t a, uint64_t b, uint64_t* lo_digit, uint64_t* hi_digit) {
  asm __volatile__ (
    "mov    x10, %[a]\n\t"        // a
    "mov    x11, %[b]\n\t"        // b
    "mov    x8, %[lo_digit]\n\t"  // &lo_digit
    "mov    x9, %[hi_digit]\n\t"  // &hi_digit
    "mul    x13, x10, x11\n\t"
    "umulh  x12, x10, x11\n\t"
    "str    x13, [x8]\n\t"
    "str    x12, [x9]\n\t"
    :: [lo_digit] "r" (lo_digit), [hi_digit] "r" (hi_digit), [a] "r" (a), [b] "r" (b) :
      "memory", "x8", "x9", "x10", "x11", "x12", "x13");
}

//  carry_out:result= a+b+carry_in
void u64_add_with_carry_step(uint64_t a, uint64_t b, uint64_t carry_in,
        uint64_t* result, uint64_t* carry_out) {
  *carry_out = carry_in << 29;
  u64_add_step(a, b, result, carry_out);
  if (*carry_out != 0ULL)
    *carry_out = 1ULL;
}

//  carry_out:result= a-b-!borrow_in if a>b+borrow_in, borrow_out=1
void u64_sub_with_borrow_step(uint64_t a, uint64_t b, uint64_t borrow_in,
                             uint64_t* result, uint64_t* borrow_out) {

  *borrow_out = borrow_in << 29;
  asm __volatile__ (
    "mov    x10, %[a]\n\t"                    // a
    "mov    x11, %[b]\n\t"                    // b
    "mov    x8, %[result]\n\t"                // &result
    "mov    x9, %[borrow_out]\n\t"            // &borrow_out
    "mrs    x13, NZCV\n\t"                    // get msr including NZCV conditions
    "mov    x14, 0xffffffff0fffffff\n\t"      // template for NZCV clear
    "and    x13, x13, x14\n\t"                // clear carry condition
    "ldr    x12, [x9]\n\t"                    // put new NZCV in x12
    "orr    x13, x13, x12\n\t"                // or in new carry condition
    "msr    NZCV, x13\n\t"                    // set NZCV
    "sbcs   x12, x10, x11\n\t"                // x12 = x10 - x11 - !C
    "mov    x13, 0\n\t"
    "cset   x13, CS\n\t"                      // get borrow flag
    "str    x12, [x8]\n\t"                    // store result
    "str    x13, [x9]\n\t"                    // carry flag to borrow_out
    :: [result] "r" (result), [borrow_out] "r" (borrow_out), [a] "r" (a), [b] "r" (b) :
      "memory", "x8", "x9", "x10", "x11", "x12", "x13", "x14");
    if (*borrow_out != 0ULL)
      *borrow_out = 1ULL;
}

//  carry_out:result= a*b+carry1+carry2
void u64_product_step(uint64_t a, uint64_t b, uint64_t mult_carry,
      uint64_t add_to, uint64_t* lo_digit, uint64_t* hi_digit) {
  uint64_t lo= 0ULL;
  uint64_t hi= 0ULL;
  uint64_t t= 0ULL;
  uint64_t carry1 = 0ULL;
  uint64_t carry2 = 0ULL;
  u64_mult_step(a, b, &lo, &hi);
  u64_add_with_carry_step(lo, mult_carry, 0ULL, &t, &carry1);
  u64_add_with_carry_step(t, add_to, 0ULL, lo_digit, &carry2);
  *hi_digit = hi + carry1 + carry2;  // no further carry
}

bool too_big(uint64_t a, uint64_t b, uint64_t c, uint64_t q) {
  uint64_t lo= 0ULL;
  uint64_t hi= 0ULL;

  u64_mult_step(q, c, &lo, &hi);
  if ((hi > a) || (hi >= a && lo > b)) {
    return true;
  }
  return false;
}

// a:b = c*q + *new_a:*new_b
bool reduce(uint64_t a, uint64_t b, uint64_t c, uint64_t q, uint64_t* new_a, uint64_t* new_b) {
  uint64_t hi = 0ULL;
  uint64_t lo = 0ULL;
  uint64_t borrow = 0ULL;

  u64_mult_step(q, c, &lo, &hi);
  u64_sub_with_borrow_step(b, lo, 1ULL, new_b, &borrow);
  u64_sub_with_borrow_step(a, hi, borrow, new_a, &borrow);
  if (borrow == 0)
    return false;
  return true;
}

void divide128x32_check(uint64_t a, uint64_t b, uint64_t c,
                        uint64_t q, uint64_t r) {
  uint64_t lo = 0ULL;
  uint64_t hi = 0ULL;
  uint64_t t = 0ULL;
  uint64_t carry = 0ULL;

  u64_mult_step(q, c, &lo, &hi);
  u64_add_with_carry_step(lo, r, 0ULL, &t, &carry);
  lo = t;
  t = 0ULL;
  u64_add_with_carry_step(hi, 0ULL, carry, &t, &carry);
  hi = t;
  if (hi != a || lo != b) {
    printf("divide128x32 check fail %016lx:%016lx != %016lx:%016lx, c: %016lx, q: %016lx, r: %016lx\n",
           a, b, hi, lo, c, q, r);
  }

  return;
}

void divide128x32(uint64_t a, uint64_t b, uint64_t c, uint64_t* q, uint64_t* r) {
  uint64_t n_t = 0ULL;
  uint64_t q_t = 0ULL;
  uint64_t r_t = 0ULL;

  n_t= (a&0xffffffff)<<32 | (b>>32);
  q_t = n_t / c;
  uint64_t t = c * q_t;
  r_t = n_t - t;
  *q= q_t << 32;
  n_t= (r_t << 32) | (b & 0xffffffff);
  q_t = n_t / c;
  r_t = n_t - c * q_t;
  *q|= q_t;
  *r= r_t;
#if 1
  divide128x32_check(a, b, c, *q, *r);
#endif
}

void divide128x64_check(uint64_t a, uint64_t b, uint64_t c,
                        uint64_t q, uint64_t r) {
  uint64_t lo = 0ULL;
  uint64_t hi = 0ULL;
  uint64_t t = 0ULL;
  uint64_t carry = 0ULL;

  u64_mult_step(q, c, &lo, &hi);
  u64_add_with_carry_step(lo, r, 0ULL, &t, &carry);
  lo = t;
  t = 0ULL;
  u64_add_with_carry_step(hi, 0ULL, carry, &t, &carry);
  hi = t;
  if (hi != a || lo != b) {
    printf("divide128x64 check fail %016lx:%016lx != %016lx:%016lx, c: %016lx, q: %016lx, r: %016lx\n",
           a, b, hi, lo, c, q, r);
  }

  return;
}


void divide128x64(uint64_t a, uint64_t b, uint64_t c, uint64_t* q, uint64_t* rem) {
  // Normalize
  int l =  high_bit_in_digit(c);
  int s = NBITSINUINT64 - l;

  uint64_t a_s = 0ULL;
  if (s == 0)
    a_s = a;
  else
    a_s = (a<<s)|(b>>l);
  uint64_t b_s = b << s;
  uint64_t c_s = c << s;
  uint64_t c_s_hi= c_s >> 32;
  *q = 0ULL;

  // Estimate and get hi 32 bits of quotient
  uint64_t q_est= a_s / c_s_hi;
  uint64_t a_s_t, b_s_t;

  if (q_est > 0xffffffffULL) {
      q_est = 0xffffffffULL;
  }
  while(too_big(a_s, b_s, c_s, q_est << 32))
    q_est--;
  *q= q_est << 32;
  if (!reduce(a_s, b_s, c_s, *q, &a_s_t, &b_s_t)) {
    printf("Reduce value is negative\n");
  }

  // Estimate and get lo 32 bits of quotient
  uint64_t t = ((a_s_t << 32) | (b_s_t >> 32));
  q_est = t / c_s_hi;

  if (q_est > 0xffffffffULL) {
      q_est = 0xffffffffULL;
  }
  while(too_big(a_s_t, b_s_t, c_s, q_est))
    q_est--;
  *q|= q_est;

  if (!reduce(a_s, b_s, c_s, *q, &a_s_t, &b_s_t)) {
    printf("Reduce value is negative\n");
  }

  // Unnormalize
  *rem = (b_s_t >> s);
#if 1
   divide128x64_check(a, b, c, *q, *rem);
#endif
}

//  q= a:b/c remainder, r
//  a < c.  a may be 0.
void u64_div_step(uint64_t a, uint64_t b, uint64_t c,
                  uint64_t* q, uint64_t* rem) {
// printf("div step: a: %016lx, b: %016lx, c: %016lx\n", a,b,c);
  if (c == 0ULL) {
    printf("divide by 0\n");
    return;
  }
  if (a > c) {
    printf("two digit answer in div step\n");
    return;
  }

  if (a != 0ULL) {
    if ((c>>32) == 0ULL) {
      divide128x32(a, b, c, q, rem);
      return;
    }
    divide128x64(a, b, c, q, rem);
    return;
  } else {
    *q = b / c;
    *rem = b - ((*q) * c); 
    return;
  }
  return;
}

// result = a+b.  returns size of result.  Error if <0
int digit_array_add(int size_a, uint64_t* a, int size_b, uint64_t* b,
      int size_result, uint64_t* result) {
  int real_size_a = digit_array_real_size(size_a, a);
  int real_size_b = digit_array_real_size(size_b, b);
  if (real_size_b > real_size_a) {
    return digit_array_add(real_size_b, b, real_size_a, a, size_result, result);
  }
  if (size_result <= real_size_a) {
    printf("digit_array_add %d <= %d\n", size_result, real_size_a);
    return -1;
  }

  uint64_t carry_in = 0ULL;
  uint64_t carry_out = 0ULL;
  int i;

  digit_array_zero_num(size_result, result);
  for (i = 0; i < real_size_b; i++) {
    u64_add_with_carry_step(a[i], b[i], carry_in, &result[i], &carry_out);
    carry_in = carry_out;
  }
  for (; i < size_a; i++) {
    u64_add_with_carry_step(a[i], 0ULL, carry_in, &result[i], &carry_out);
    carry_in = carry_out;
  }
  if (carry_out != 0) {
    if (i > size_result) {
      printf("digit_array_add %d >= %d\n", i, size_result);
      return -1;
    }
    result[i] = carry_out;
  }
  return digit_array_real_size(size_result, result);
}

// result = a-b.  returns size of result.  Error if <0
// constraint: a>b
int digit_array_sub(int size_a, uint64_t* a, int size_b, uint64_t* b,
                    int size_result, uint64_t* result) {
  uint64_t borrow_in = 1;
  uint64_t borrow_out = 0;

  int real_size_a = digit_array_real_size(size_a, a);
  int real_size_b = digit_array_real_size(size_b, b);
  if (real_size_a > size_result) {
    return -1;
  }
  if (digit_array_compare(real_size_a, a, real_size_b, b) < 0)
    return -1;

  int i;
  digit_array_zero_num(size_result, result);
  for (i = 0; i < size_b; i++) {
    u64_sub_with_borrow_step(a[i], b[i], borrow_in, &result[i], &borrow_out);
    borrow_in = borrow_out;
  }
  for (; i < size_a; i++) {
    u64_sub_with_borrow_step(a[i], 0ULL, borrow_in, &result[i], &borrow_out);
    borrow_in = borrow_out;
  }
  return digit_array_real_size(size_result, result);
}

// a+= b
int digit_array_add_to(int capacity_a, int size_a, uint64_t* a, int size_b,
                    uint64_t* b) {
  int real_size_a = digit_array_real_size(size_a, a);
  int real_size_b = digit_array_real_size(size_b, b);

  int c_size = capacity_a + 1;
  uint64_t c[c_size];

  digit_array_zero_num(capacity_a, c);
  int i = digit_array_add(real_size_a, a, real_size_b, b, c_size, c);
  if (i < 0) {
    printf("digit_array_add fails in add_to; cap_a: %d, real_siaze_a: %d, real_size_b: %d\n",
             capacity_a, real_size_a, real_size_b);
    return -1;
  }
  if (i > capacity_a)
    return -1;
  if (!digit_array_copy(capacity_a, c, capacity_a, a))
    return -1;
  return i;
}

// a-= b
int digit_array_sub_from(int capacity_a, int size_a, uint64_t* a, int size_b,
                      uint64_t* b) {
  int real_size_a = digit_array_real_size(size_a, a);
  int real_size_b = digit_array_real_size(size_b, b);
  if (real_size_a < real_size_b) {
    printf("digit_array_sub fails %d <  %d\n", real_size_a, real_size_b);
    return -1;
  }

  uint64_t c[capacity_a];
  digit_array_zero_num(capacity_a, c);
  int i = digit_array_sub(capacity_a, a, real_size_b, b, capacity_a, c);
  if (i < 0) {
    printf("digit_array_sub fails cap_a: %d, real_size_b: %d\n", capacity_a, real_size_b);
    return -1;
  }
  digit_array_zero_num(capacity_a, a);
  if (!digit_array_copy(i, c, capacity_a, a))
    return -1;
  return i;
}

// result = a*b.  returns size of result.  Error if < 0
int digit_array_mult(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_result, uint64_t* result) {
  // output is size_a+size_b or size_a+size_b-1 uint64_t elements
  int real_size_a = digit_array_real_size(size_a, a);
  int real_size_b = digit_array_real_size(size_b, b);
  if ((real_size_a + real_size_b) > size_result) {
    return -1;
  }
  digit_array_zero_num(size_result, result);

  int i, j, k;
  uint64_t mult_carry= 0ULL;
  uint64_t carry_out = 0ULL;

  for (i = 0; i < real_size_a; i++) {
    mult_carry = 0ULL;
    for (j = 0; j < real_size_b; j++) {
      u64_product_step(a[i], b[j], mult_carry, result[i+j], &result[i+j], &carry_out);
      mult_carry= carry_out;
    }

    k= i + j;
    for(; (k < size_result) && (mult_carry != 0ULL); k++) {
      u64_add_with_carry_step(result[k], mult_carry, 0ULL,
        &result[k], &carry_out);
      mult_carry = carry_out;
    }
  }
  return digit_array_real_size(size_result, result);
}

// result = a*a.  returns size of result.  Error if <0
int digit_array_square(int size_a, uint64_t* a, int size_result,
                     uint64_t* result) {
  int real_size_a = digit_array_real_size(size_a, a);
  if ((real_size_a + real_size_a) > size_result) {
    return -1;
  }
  return digit_array_mult(size_a, a, size_a, a, size_result, result);
}

// a*= x.  a must have size_a+1 positions available
int digit_array_mult_by(int capacity_a, int size_a, uint64_t* a, uint64_t x) {
  uint64_t hi= 0ULL;
  uint64_t lo= 0ULL;
  uint64_t carry= 0ULL;
  int real_size_a = digit_array_real_size(size_a, a);
  if (capacity_a <= real_size_a)
    return -1;

  int i;
  for (i = 0; i < real_size_a; i++) {
    u64_mult_step(a[i], x, &lo, &hi);
    u64_add_with_carry_step(lo, carry, 0ULL, &a[i], &carry);
    carry += hi;
  }
  a[i]= carry;

  return digit_array_real_size(capacity_a, a);
}

bool digit_array_short_division_algorithm(int size_a, uint64_t* a, uint64_t b,
         int* size_q, uint64_t* q, uint64_t* r) {
  int real_size_a = digit_array_real_size(size_a, a);
  uint64_t* a_high = &a[real_size_a - 1];
  uint64_t* q_high = &q[real_size_a - 1];

  uint64_t rem = 0ULL;
  for (int i = 0; i < real_size_a; i++) {
    *r = 0ULL;
    u64_div_step(rem, *a_high, b, q_high, r);
    rem = *r;
    a_high--;
    q_high--;
  }

  *size_q = digit_array_real_size(*size_q, q);
  return true;
}

// estimate quotient (cf: Knuth v2)
// *est-2<= q <= *est
// note b1>0 and (a1 a2)_b >= b1_b, b= 2^64
void estimate_quotient(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t b1,
                       uint64_t b2, uint64_t* est) {
  uint64_t n1 = 0ULL;
  uint64_t n2 = 0ULL;
  uint64_t d1;
  int den_shift = shift_to_top_bit(b1);

  if (den_shift == 0) {
    d1 = b1;
    n1 = a1;
    n2 = a2;
  } else {
    n1 = (a1 << den_shift) | (a2 >> (NBITSINUINT64 - den_shift));
    n2 = (a2 << den_shift) | (a3 >> (NBITSINUINT64 - den_shift));
    d1 = (b1 << den_shift) | (b2 >> (NBITSINUINT64 - den_shift));
  }

  if (n1 > d1) {
    *est = (uint64_t)-1;
    return;
  }

  uint64_t r= 0ULL;;
  u64_div_step(n1, n2, d1, est, &r);
}

// q= a/b. r is remainder.
bool digit_array_division_algorithm(int size_a, uint64_t* a, int size_b,
       uint64_t* b, int* size_q, uint64_t* q, int* size_r, uint64_t* r) {
  int real_size_a = digit_array_real_size(size_a, a);
  int real_size_b = digit_array_real_size(size_b, b);

  if (real_size_b == 1) {
    if (b[0] == 0ULL) {
      printf("digit_array_division_algorithm, zero divide\n");
      return false;
    }
    return digit_array_short_division_algorithm(real_size_a, a, b[0],
                 size_q, q, &r[0]);
  }

  int hi_quotient_digit = real_size_a - real_size_b;
  uint64_t x;
  int i, m, n;
  int real_size_r;
  int real_size_y;
  int cmp;

  digit_array_zero_num(*size_q, q);
  digit_array_zero_num(*size_r, r);
  if (*size_r < real_size_a)
    return false;
  if (!digit_array_copy(real_size_a, a, *size_r, r)) {
    printf("digit_array_division_algorithm remainder size is too small\n");
    return false;
  }

  uint64_t y[real_size_a + 1];
  int size_y = real_size_a + 1;

  real_size_r = real_size_a;
  for (i = hi_quotient_digit; i >= 0; i--) {
    real_size_r = digit_array_real_size(*size_r, r);
    cmp = digit_array_compare(real_size_b, b, real_size_r, r);
    if (cmp > 1)
      break;
    n = real_size_b + i;
    if (n == real_size_a) {
      estimate_quotient(0ULL, r[n - 1], r[n - 2], b[real_size_b - 1],
                       b[real_size_b - 2], &x);
    } else if (n < 2) {
      estimate_quotient(r[n], r[n - 1], 0ULL, b[real_size_b - 1],
                       b[real_size_b - 2], &x);
    } else {
      estimate_quotient(r[n], r[n - 1], r[n - 2], b[real_size_b - 1],
                       b[real_size_b - 2], &x);
    }
    for (;;) {
      if (x == 0ULL)
        break;
      digit_array_zero_num(size_y, y);
      if (digit_array_mult(real_size_b, b, 1, &x, size_y - i, &y[i]) < 0) {
      }
      real_size_y = digit_array_real_size(size_y, y);
      m = digit_array_compare(real_size_y, y, real_size_r, r);
      if (x == 0ULL || m <= 0) {
        break;
      }
      x--;
    }
    if (x == 0) {
      continue;
    }
    digit_array_sub_from(*size_r, real_size_r, r, real_size_y, y);
    q[i] = x;
  }

  // set quotient and remainder sizes
  int nq = digit_array_real_size(*size_q, q);
  *size_q = nq;
  int nr = digit_array_real_size(*size_r, r);
  *size_r = nr;
  return true;
}

bool digit_convert_to_decimal(int size_n, uint64_t* n, string* s) {
  s->clear();
  int ns = digit_array_real_size(size_n, n);
  uint64_t a[ns];
  uint64_t q[ns];
  uint64_t r = 0;

  if (!digit_array_copy(ns, n, ns, a))
    return false;
  int size_q;

  for(;;) {
    size_q = ns;
    digit_array_zero_num(ns, q);

    if (!digit_array_short_division_algorithm(digit_array_real_size(ns, a), a,
            10ULL, &size_q, q, &r))
      return false;
    s->append(1, (char)r + '0');

    if (size_q == 1 && q[0] == 0ULL)
      break;
    if (!digit_array_copy(ns, q, ns, a))
      return false;
  }

  reverse_bytes_in_place(s->size(), (byte_t*) s->data());
  s->append(1, '\0');
  return true;
}

bool digit_convert_from_decimal(string& s, int size_n, uint64_t* n) {
  digit_array_zero_num(size_n, n);
  uint64_t digit;

  int sn = strlen(s.c_str());
  sn = (sn + 2) / 3;  // number of 10 bit number slots needed
  sn *= 10;
  sn = (sn + NBITSINBYTE - 1) / NBITSINBYTE;
  int m = (sn + sizeof(uint64_t) - 1) / sizeof(uint64_t);
  if (m > (size_n - 1))
    return false;

  const char *p = s.c_str();
  while (*p != '\0') {
    if (digit_array_mult_by(size_n, digit_array_real_size(size_n, n), n, 10ULL) < 0)
      return false;
    digit = (uint64_t)(*p - '0');
    if (digit_array_add_to(size_n, digit_array_real_size(size_n, n), n, 1, &digit) < 0)
      return false;
    p++;
  }
  return true;
}
