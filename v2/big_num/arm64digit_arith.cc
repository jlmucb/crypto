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
    printf("%016llx ", a[j]);
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
    "str    x11, [X9]\n\t"
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

//  carry_out:result= a-b-borrow_in if a>b+borrow_in, borrow_out=0
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
    "sbc    x12, x10, x11\n\t"                // x12 = x10 - x11 - !C
    "cset   x13, CS\n\t"                      // get carry flag
    "str    x12, [x8]\n\t"                    // store result
    "str    x13, [x9]\n\t"                    // carry flag to borrow_out
    :: [result] "r" (result), [borrow_out] "r" (borrow_out), [a] "r" (a), [b] "r" (b) :
      "memory", "x8", "x9", "x10", "x11", "x12", "x13", "x14");
    if (*borrow_out != 0ULL)
      *borrow_out = 1ULL;
}

//  carry_out:result= a*b+carry1+carry2
void u64_mult_with_carry_step(uint64_t a, uint64_t b, uint64_t carry1,
      uint64_t carry2, uint64_t* lo_digit, uint64_t* hi_digit) {
  uint64_t add_carry1= 0ULL;
  uint64_t add_carry2= 0ULL;
  uint64_t add_carry= 0ULL;
  uint64_t t1, t2, t3;

  u64_mult_step(a, b, &t1, &t2);
  u64_add_with_carry_step(t1, carry1, 0ULL, &t3, &add_carry1);
  u64_add_with_carry_step(t3, carry2, add_carry1, lo_digit, &add_carry2);
  if (add_carry2 != 0 ) {
    u64_add_with_carry_step(t2, add_carry2, 0ULL, hi_digit, &add_carry);
  }  else {
    *hi_digit = t2;
  }
}

bool correct_q(uint64_t a, uint64_t b, uint64_t c, uint64_t q) {
  uint64_t lo_digit;
  uint64_t hi_digit;
  u64_mult_step(q, c, &lo_digit, &hi_digit);
  if (hi_digit > a || (hi_digit == a && lo_digit >=b)) {
    return false;
  }
  return true;
}

//  q= a:b/c remainder, r
void u64_div_step(uint64_t a, uint64_t b, uint64_t c,
                  uint64_t* q, uint64_t* rem) {

  int i;

  // we have to estimate and correct since there are no two digit quotients
  uint64_t b1, c1;
  if (a > 0 ) {
    i = high_bit_in_digit(a);
    b1 = (b >> i) | (a << (NBITSINUINT64 - i));
    c1 = c >> i;
  } else {
    b1 = b;
    c1 = c;
  }

  asm __volatile__ (
    "mov    x11, %[b1]\n\t"       // b1
    "mov    x12, %[c1]\n\t"       // c1
    "mov    x8, %[q]\n\t"         // q
    "mov    x9, %[rem]\n\t"       // rem
    "udiv   x10, x11, x12\n\t"    // x10= x11 / x12
    "str    x10, [x8]\n\t"        // store q
    "str    x12, [x9]\n\t"        // store rem
    :: [b1] "r" (b1), [c1] "r" (c1), [q] "r" (q), [rem] "r" (rem):
      "memory", "cc", "x8", "x9", "x10", "x11", "x12", "x13");

  // now correct estimate (it's an overestimate)
  if (*q == 0ULL) {
    *rem = b;
    return;
  }

  // Is *q * c > a:b
  while (correct_q(a, b, c, *q)) {
    (*q)--;
  }

  uint64_t lo_digit;
  uint64_t hi_digit;
  uint64_t borrow;
  uint64_t r;
  u64_mult_step(c, *q, &lo_digit, &hi_digit);
  u64_sub_with_borrow_step(a, hi_digit, 0ULL, &r, &borrow);
  u64_sub_with_borrow_step(b, lo_digit, 0ULL, rem, &borrow);
}

// result = a+b.  returns size of result.  Error if <0
int digit_array_add(int size_a, uint64_t* a, int size_b, uint64_t* b,
      int size_result, uint64_t* result) {
  int real_size_a = digit_array_real_size(size_a, a);
  int real_size_b = digit_array_real_size(size_b, b);
  if (real_size_b > real_size_a)
    return digit_array_add(real_size_b, b, real_size_a, a, size_result, result);
  if (size_result <= real_size_a)
    return -1;

  uint64_t carry_in = 0ULL;
  uint64_t carry_out = 0ULL;
  int i;

  digit_array_zero_num(size_result, result);
  for (i = 0; i < size_b; i++) {
    u64_add_with_carry_step(a[i], b[i], carry_in, &result[i], &carry_out);
    carry_in = carry_out;
  }
  for (; i < size_a; i++) {
    u64_add_with_carry_step(a[i], 0ULL, carry_in, &result[i], &carry_out);
    carry_in = carry_out;
  }
  if (carry_out != 0) {
    if (i >= size_result)
      return -1;
    result[i] = carry_out;
  }
  return digit_array_real_size(size_result, result);
}

// result = a-b.  returns size of result.  Error if <0
// constraint: a>b
int digit_array_sub(int size_a, uint64_t* a, int size_b, uint64_t* b,
                    int size_result, uint64_t* result) {
  uint64_t borrow_in = 0;
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
  int64_t len_a = (int64_t)size_a;
  int64_t len_b = (int64_t)size_b;

  return digit_array_real_size(capacity_a, a);
}

// a-= b
int digit_array_sub_from(int capacity_a, int size_a, uint64_t* a, int size_b,
                      uint64_t* b) {
  if (size_a < size_b)
    return -1;

  int64_t len_a = (int64_t)size_a;
  int64_t len_b = (int64_t)size_b;


  return digit_array_real_size(capacity_a, a);
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

#ifdef FASTMULT
  uint64_t carry = 0;
  uint64_t real_size_A = (uint64_t) real_size_a;
  uint64_t real_size_B = (uint64_t) real_size_b;

#else
  int i, j;
  uint64_t carry_in = 0;
  uint64_t carry_out = 0;

  for (i = 0; i < real_size_a; i++) {
    carry_in = 0;
    for (j = 0; j < real_size_b; j++) {
      carry_out = 0;
     u64_mult_with_carry_step(a[i], b[j], carry_in, result[i + j],
                              &result[i + j], &carry_out);
      carry_in = carry_out;
    }
    result[i + j] = carry_out;
  }
#endif
  return digit_array_real_size(size_result, result);
}

// result = a*a.  returns size of result.  Error if <0
int digit_array_square(int size_a, uint64_t* a, int size_result,
                     uint64_t* result) {
  int real_size_a = digit_array_real_size(size_a, a);
  if ((real_size_a + real_size_a) > size_result) {
    return -1;
  }

#ifdef FASTSQUARE
  uint64_t cur_in = 0ULL;
  uint64_t cur_out = 0ULL;

  return digit_array_real_size(size_result, result);
#else
  return digit_array_mult(size_a, a, size_a, a, size_result, result);
#endif
}

// a*= x.  a must have size_a+1 positions available
int digit_array_mult_by(int capacity_a, int size_a, uint64_t* a, uint64_t x) {
  // Todo

  return digit_array_real_size(size_a, a);
}

bool digit_array_short_division_algorithm(int size_a, uint64_t* a, uint64_t b,
         int* size_q, uint64_t* q, uint64_t* r) {
  int real_size_a = digit_array_real_size(size_a, a);
  uint64_t len_a = (uint64_t)real_size_a;
  uint64_t* a_high = &a[real_size_a - 1];
  uint64_t* q_high = &q[real_size_a - 1];

  // Todo

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

  uint64_t r;
  u64_div_step(a1, a2, b2, est, &r);
}

// q= a/b. r is remainder.
bool digit_array_division_algorithm(int size_a, uint64_t* a, int size_b,
       uint64_t* b, int* size_q, uint64_t* q, int* size_r, uint64_t* r) {
  int real_size_a = digit_array_real_size(size_a, a);
  int real_size_b = digit_array_real_size(size_b, b);

  if (real_size_b == 1) {
    if (b[0] == 0ULL) {
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
  if (!digit_array_copy(size_a, a, *size_r, r)) {
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

  int  ns = digit_array_real_size(size_n, n);
  uint64_t* t = new uint64_t[ns];
  if (t == nullptr)
    return false;
  for (int j = 0; j < ns; j++)
    t[j] = n[j];

  if (ns == 1 && t[0] == 0ULL) {
    s->append(1, '0');
    goto done;
  }

  uint64_t q, r;
  while (ns > 0) {

    if (t[ns - 1] == 0ULL) {
      ns--;
      continue;
    }
   
    r = 0ULL;
    for (int j = (ns - 1); j >= 0; j--) {
      if (r == 0ULL) {
        q = t[j] / 10;
        r = t[j] - q * 10;
        t[j] = q;
      } else {
        u64_div_step(r, t[j], 10, &q, &r) ;
        t[j] = q;
      }
    }
    s->append(1, '0' + r);
  }

  reverse_bytes_in_place(s->size(), (byte*) s->data());
  s->append(1, '\0');

done:
  delete []t;
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
