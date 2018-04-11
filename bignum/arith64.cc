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
// Project: New Cloudproxy Crypto
// File: intel64_arith.cc

#include "cryptotypes.h"
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "bignum.h"
#include "conversions.h"
#include "util.h"

// ------------------------------------------------------------------------

void TempPrintNum(int size_a, uint64_t* a) {
  int i;

  for (i = (size_a - 1); i >= 0; i--)
    printf("%016lx ", (unsigned long)a[i]);
}

int DigitArrayComputedSize(int size_a, uint64_t* a) {
  int n;

  for (n = (size_a - 1); n > 0; n--) {
    if (a[n] != 0ULL)
      break;
  }
  return n + 1;
}

bool DigitArrayIsZero(int size_a, uint64_t* a) {
  int i;

  for (i = 0; i < size_a; i++) {
    if (a[i] != 0ULL)
      return false;
  }
  return true;
}

void DigitArrayZeroNum(int size_a, uint64_t* a) {
  int i;

  for (i = 0; i < size_a; i++) a[i] = 0ULL;
}

// copy a-->b
bool DigitArrayCopy(int size_a, uint64_t* a, int size_b, uint64_t* b) {
  int i;

  if (size_b < size_a)
    return false;

  for (i = 0; i < size_a; i++) {
    b[i] = a[i];
  }
  return true;
}

int DigitArrayShiftUp(int size_a, uint64_t* a, int shift, int size_r,
                      uint64_t* r) {
  int word_shift = shift / NBITSINUINT64;
  int partial_word_shift = shift - word_shift * NBITSINUINT64;
  int i;
  uint64_t x = 0ULL;

  if ((size_a + word_shift) >= size_r)
    return -1;

  DigitArrayZeroNum(size_r, r);
  for (i = (size_a - 1); i >= 0; i--) {
    x = a[i];
    if (partial_word_shift != 0)
      r[i + word_shift + 1] |= x >> (NBITSINUINT64 - partial_word_shift);
    r[i + word_shift] |= x << partial_word_shift;
  }
  return DigitArrayComputedSize(size_r, r);
}

int DigitArrayShiftDown(int size_a, uint64_t* a, int shift, int size_r,
                        uint64_t* r) {
  int word_shift = shift / NBITSINUINT64;
  int partial_word_shift = shift - word_shift * NBITSINUINT64;
  int i;
  uint64_t x = 0ULL;

  if ((size_a - word_shift - 1) >= size_r)
    return -1;

  DigitArrayZeroNum(size_r, r);
  for (i = (size_a - word_shift - 1); i >= 0; i--) {
    x = a[i + word_shift];
    r[i] |= x >> partial_word_shift;
    if (i > 0 && partial_word_shift != 0)
      r[i - 1] |= x << (NBITSINUINT64 - partial_word_shift);
  }
  return DigitArrayComputedSize(size_r, r);
}

// returns  1, if a>b
// returns  0, if a==b
// returns -1, if a<b
int DigitArrayCompare(int size_a, uint64_t* a, int size_b, uint64_t* b) {
  int i;
  int real_size_a = DigitArrayComputedSize(size_a, a);
  int real_size_b = DigitArrayComputedSize(size_b, b);

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

int HighBitInDigit(uint64_t a) {
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

// q= a/b. r is remainder.
bool DigitArrayDivisionAlgorithm(int size_a, uint64_t* a, int size_b,
                                 uint64_t* b, int* size_q, uint64_t* q,
                                 int* size_r, uint64_t* r) {
  int real_size_a = DigitArrayComputedSize(size_a, a);
  int real_size_b = DigitArrayComputedSize(size_b, b);

  if (real_size_b == 1) {
    if (b[0] == 0ULL) {
      LOG(ERROR) << "b[0]==0 DigitArrayDivisionAlgorithm failure\n";
      return false;
    }
    return DigitArrayShortDivisionAlgorithm(real_size_a, a, b[0], size_q, q,
                                            &r[0]);
  }

  int hi_quotient_digit = real_size_a - real_size_b;
  uint64_t x;
  int i, m, n;
  int real_size_r;
  int real_size_y;
  int cmp;

  DigitArrayZeroNum(*size_q, q);
  DigitArrayZeroNum(*size_r, r);
  if (!DigitArrayCopy(size_a, a, *size_r, r)) {
    LOG(ERROR) << "DigitArrayCopy 1 error\n";
    return false;
  }

  uint64_t y[real_size_a + 1];
  int size_y = real_size_a + 1;

  real_size_r = real_size_a;
  for (i = hi_quotient_digit; i >= 0; i--) {
    real_size_r = DigitArrayComputedSize(*size_r, r);
    cmp = DigitArrayCompare(real_size_b, b, real_size_r, r);
    if (cmp > 1)
      break;
    n = real_size_b + i;
    if (n == real_size_a) {
      EstimateQuotient(0ULL, r[n - 1], r[n - 2], b[real_size_b - 1],
                       b[real_size_b - 2], &x);
    } else if (n < 2) {
      EstimateQuotient(r[n], r[n - 1], 0ULL, b[real_size_b - 1],
                       b[real_size_b - 2], &x);
    } else {
      EstimateQuotient(r[n], r[n - 1], r[n - 2], b[real_size_b - 1],
                       b[real_size_b - 2], &x);
    }
    for (;;) {
      if (x == 0ULL)
        break;
      DigitArrayZeroNum(size_y, y);
      if (DigitArrayMult(real_size_b, b, 1, &x, size_y - i, &y[i]) < 0) {
        LOG(ERROR) << "DigitArrayMult in DigitArrayDivisionAlgorithm\n";
      }
      real_size_y = DigitArrayComputedSize(size_y, y);
      m = DigitArrayCompare(real_size_y, y, real_size_r, r);
      if (x == 0ULL || m <= 0) {
        break;
      }
      x--;
    }
    if (x == 0) {
      continue;
    }
    DigitArraySubFrom(*size_r, real_size_r, r, real_size_y, y);
    q[i] = x;
  }

  // set quotient and remainder sizes
  int nq = DigitArrayComputedSize(*size_q, q);
  *size_q = nq;
  int nr = DigitArrayComputedSize(*size_r, r);
  *size_r = nr;
  return true;
}

bool DigitArrayConvertToDecimal(int size_a, uint64_t* a, int* size_s, char* s) {
  int real_size_a = DigitArrayComputedSize(size_a, a);
  int src = 0;
  int dst = 1;
  uint64_t* t[2];
  uint64_t r = 0ULL;
  int i, m;
  int num_dec_digits = 0;
  char* new_s = new char[*size_s];
  volatile uint64_t ten = (uint64_t)10;

  t[0] = new uint64_t[real_size_a];
  t[1] = new uint64_t[real_size_a];
  DigitArrayZeroNum(real_size_a, t[0]);
  if (!DigitArrayCopy(real_size_a, a, real_size_a, t[0])) return false;
  for (;;) {
    m = DigitArrayComputedSize(real_size_a, t[src]);
    DigitArrayZeroNum(real_size_a, t[dst]);
    if (!DigitArrayShortDivisionAlgorithm(real_size_a, t[src], ten, &m, t[dst],
                                          &r))
      return false;

    new_s[num_dec_digits++] = (char)r + '0';
    if (DigitArrayIsZero(real_size_a, t[dst])) {
      break;
    }
    src = (src + 1) % 2;
    dst = (dst + 1) % 2;
  }

  if (num_dec_digits == 0) {
    new_s[num_dec_digits++] = ((char)'0');
  }
  new_s[num_dec_digits] = 0;

  // reverse the digits now
  m = num_dec_digits;
  for (i = 0; i < num_dec_digits; i++) {
    s[i] = new_s[--m];
  }
  s[i] = 0;
  delete t[0];
  delete t[1];
  delete []new_s;

  return true;
}

bool DigitArrayConvertToHex(int size_a, uint64_t* a, int* size_s, char* s) {
  int real_size_a = DigitArrayComputedSize(size_a, a);
  int i;
  int n = real_size_a * sizeof(uint64_t);
  byte* p = (byte*)&a[real_size_a];
  byte b;

  p--;
  for (i = 0; i < n; i++) {
    b = *(p--);
    s[2 * i] = ValueToHex(b >> 4);
    s[2 * i + 1] = ValueToHex((b & 0xf));
  }
  s[2 * i] = 0;
  return true;
}

int DigitArrayConvertFromDecimal(const char* s, int size_a, uint64_t* a) {
  int n = strlen(s);
  const char* p = s;
  byte b;
  uint64_t x;
  volatile uint64_t ten = 10ULL;
  int real_size_a;

  if (30 * size_a < n)
    return -1;
  DigitArrayZeroNum(size_a, a);
  while (n > 0) {
    b = HexToValue(*(p++));
    x = (uint64_t)b;
    real_size_a = DigitArrayComputedSize(size_a, a);
    DigitArrayMultBy(size_a, real_size_a, a, ten);
    real_size_a = DigitArrayComputedSize(size_a, a);
    DigitArrayAddTo(size_a, real_size_a, a, 1, &x);
    n--;
  }
  return DigitArrayComputedSize(size_a, a);
}

int DigitArrayConvertFromHex(const char* s, int size_a, uint64_t* a) {
  int n = strlen(s);
  const char* p = s;
  byte b;
  uint64_t x;
  int real_size_a;

  if (16 * size_a < n) {
    LOG(ERROR) << "number size too small for hex";
    return -1;
  }
  DigitArrayZeroNum(size_a, a);
  while (n > 0) {
    b = HexToValue(*(p++));
    x = (uint64_t)b;
    real_size_a = DigitArrayComputedSize(size_a, a);
    DigitArrayMultBy(size_a, real_size_a, a, 16ULL);
    real_size_a = DigitArrayComputedSize(size_a, a);
    DigitArrayAddTo(size_a, real_size_a, a, 1, &x);
    n--;
  }
  return DigitArrayComputedSize(size_a, a);
}

// result = a+b.  returns size of result.  Error if <0
int DigitArrayAdd(int size_a, uint64_t* a, int size_b, uint64_t* b,
                  int size_result, uint64_t* result) {
  if (size_b > size_a)
    return DigitArrayAdd(size_b, b, size_a, a, size_result, result);
  if (size_result < size_a)
    return -1;

  uint64_t carry_in = 0ULL;
  uint64_t carry_out = 0ULL;
  int i;

  DigitArrayZeroNum(size_result, result);
  for (i = 0; i < size_b; i++) {
    Uint64AddWithCarryStep(a[i], b[i], carry_in, &result[i], &carry_out);
    carry_in = carry_out;
  }
  for (; i < size_a; i++) {
    Uint64AddWithCarryStep(a[i], 0ULL, carry_in, &result[i], &carry_out);
    carry_in = carry_out;
  }
  if (carry_out != 0) {
    if (i >= size_result)
      return -1;
    result[i] = carry_out;
  }
  return DigitArrayComputedSize(size_result, result);
}

// result = a-b.  returns size of result.  Error if <0
// constraint: a>b
int DigitArraySub(int size_a, uint64_t* a, int size_b, uint64_t* b,
                  int size_result, uint64_t* result) {
  int i;
  uint64_t borrow_in = 0;
  uint64_t borrow_out = 0;

  // note: size_a>=size_b
  if (size_a > size_result) {
    LOG(ERROR) << "DigitArraySub: result is too small\n";
    return -1;
  }
  DigitArrayZeroNum(size_result, result);
  for (i = 0; i < size_b; i++) {
    Uint64SubWithBorrowStep(a[i], b[i], borrow_in, &result[i], &borrow_out);
    borrow_in = borrow_out;
  }
  for (; i < size_a; i++) {
    Uint64SubWithBorrowStep(a[i], 0ULL, borrow_in, &result[i], &borrow_out);
    borrow_in = borrow_out;
  }
  return DigitArrayComputedSize(size_result, result);
}
