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
// File: arm64_arith.cc

#include "cryptotypes.h"
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "bignum.h"
#include "conversions.h"
#include "util.h"

#define FASTMULT
#define FASTSQUARE

// FIX!!!

// Uint64AddStep
// Uint64SubStep
// Uint64MultStep
// Uint64DivStep
// Uint64AddWithCarryStep
// Uint64SubWithBorrowStep
// Uint64MultWithCarryStep
// DigitArrayShortDivisionAlgorithm
// DigitArrayMult
// AddTo
// Subtraction (num1>=num2)
// Multiplication (size2 >= size1)
// Division (size2 >= size1)
// Square
// Estimate quotient

// Addition (draft)
//  size2 >= size1
asm volatile (
    "\tldr     x9, num1\n"    // input 1
    "\tldr     x10, num2\n"   // input 2
    "\tldr     x11, num3\n"   // output
    "\tldr     x12, #0\n"     // index
"lp1:\n"
    // do while x12 < size1, size2
    "\tldr     x13, #0\n"
    "\tcmp     x12, [size1]\n"
    "\tb.ge    skp\n"
    "\tldr     x13, [x9, x12, lsl #3]\n"
"skp:\n"
    "\tldr     x14, [x10, x12, lsl #3]\n"
    "\tuaddc   x15, x14, x13\n"
    "\tstr     x16, [x11, x12, lsl #3]\n"
    "\tadd     x12, #1\n"
    "\tcmp     x12, [size2]\n"
    "\tb.g     lp1\n"
"out:\n"
    "\tb.nc    nc\n"
    "\tldr     x15, #1\n"
    "\tstr     x15, [x11, x12, lsl #3]\n"
"nc:\n"
    : [num1] "=m" (num1), [num2] "=m" (num2), [num3] "=m" (num3), [size1] "=m" (size1), [size2] "=m" (size2),
    :"cc", "memory", "x9", "x10", "x11", "x12", "x13", "x14", "x15");

/*
    [U|S]MULL r4, r5, r2, r3 ; r5 : r4 = r2 * r3

    UDIV Wd, Wn, Wm
    Unsigned Divide: Wd = Wn ÷ Wm, treating source operands as unsigned. 
    The UMLAL instruction interprets the values from Rn and Rm as unsigned integers. It multiplies 
    these integers, adds the 64-bit result to the 64-bit unsigned integer contained in RdHi and 
    RdLo, and writes the result back to RdHi and RdLo.
 */


// ------------------------------------------------------------------------

// Estimate quotient (cf: Knuth v2)
// *est = (a1 * b + a2) / b1.
// When b1 > b/2, *est-2 <= q <= *est.
// We can always cause this to happen by multiplying numerator
// and denominator by a scaling factor if necessary.
// We can scale by just shifting from b2 and a3 as needed.
void EstimateQuotient(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t b1,
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

  // estimate
  asm volatile(
      ::[est] "g"(est), [n1] "g"(n1), [n2] "g"(n2), [d1] "g"(d1)
      : "cc", "memory", "x1");
}

//  carry : result= a + b.
void Uint64AddStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry) {
  asm volatile(
      ::[result] "g"(result), [carry] "g"(carry), [a] "g"(a), [b] "g"(b)
      : "cc", "memory", "x9");
}

//  result= a - b, borrow.
void Uint64SubStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t* borrow) {
}

//  carry : result= a * b.
void Uint64MultStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry) {
  asm volatile(
      ::[result] "g"(result),
      [carry] "g"(carry), [a] "g"(a), [b] "g"(b)
      : "cc", "memory", "x9");
}

//  q = (a : b) / c remainder, r.
void Uint64DivStep(uint64_t a, uint64_t b, uint64_t c, uint64_t* result,
                   uint64_t* rem) {
  asm volatile(
      ::[result] "m"(result), [rem] "m"(rem),
        [a] "m"(a), [b] "m"(b), [c] "m"(c)
      : "cc", "memory", "x9");
}

//  carry_out : result= a + b + carry_in.
void Uint64AddWithCarryStep(uint64_t a, uint64_t b, uint64_t carry_in,
                            uint64_t* result, uint64_t* carry_out) {
  asm volatile(
      ::[result] "g"(result), [carry_out] "g"(carry_out), [a] "g"(a),
      [b] "g"(b), [carry_in] "g"(carry_in)
      : "cc", "memory", "x9");
}

//  carry_out : result= a - b - borrow_in.  If a > b + borrow_in, borrow_out=0.
void Uint64SubWithBorrowStep(uint64_t a, uint64_t b, uint64_t borrow_in,
                             uint64_t* result, uint64_t* borrow_out) {
  asm volatile(
      ::[result] "g"(result), [borrow_out] "g"(borrow_out), [a] "g"(a),
      [b] "g"(b), [borrow_in] "g"(borrow_in)
      : "cc", "memory", "x9");
}

//  carry_out : result= a * b + carry1 + carry2.
void Uint64MultWithCarryStep(uint64_t a, uint64_t b, uint64_t carry1,
                             uint64_t carry2, uint64_t* result,
                             uint64_t* carry_out) {
  asm volatile(
      ::[a] "g"(a), [b] "g"(b), [carry1] "g"(carry1), [carry2] "g"(carry2),
      [result] "g"(result), [carry_out] "g"(carry_out)
      : "cc", "memory", "x9");
}

// result = a * b.  returns size of result, or < 0 if there is an error.
int DigitArrayMult(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_result, uint64_t* result) {
  // output is size_a + size_b or size_a + size_b - 1 uint64_t elements
  if ((size_a + size_b) > size_result) {
    LOG(ERROR) << "DigitArrayMult: result is too small\n";
    return -1;
  }
  DigitArrayZeroNum(size_result, result);

#ifdef FASTMULT
  uint64_t carry = 0;
  uint64_t size_A = (uint64_t)size_a;
  uint64_t size_B = (uint64_t)size_b;

  //  Caller ensures out is large enough.
  asm volatile(
      ::[carry] "m"(carry), [in1] "g"(a), [in2] "g"(b), [size_A] "g"(size_A),
        [size_B] "g"(size_B), [result] "g"(result)
      : "memory", "cc", "x9");
#else
  int i, j;
  uint64_t carry_in = 0;
  uint64_t carry_out = 0;

  for (i = 0; i < size_a; i++) {
    carry_in = 0;
    for (j = 0; j < size_b; j++) {
      carry_out = 0;
      Uint64MultWithCarryStep(a[i], b[j], carry_in, result[i + j],
                              &result[i + j], &carry_out);
      carry_in = carry_out;
    }
    result[i + j] = carry_out;
  }
#endif
  return DigitArrayComputedSize(size_result, result);
}

// result = a * a.  returns size of result, error if < 0.
int DigitArraySquare(int size_a, uint64_t* a, int size_result,
                     uint64_t* result) {
  if ((size_a + size_a) > size_result) {
    LOG(ERROR) << "DigitArraySquare: result is too small\n";
    return -1;
  }

#ifdef FASTSQUARE
  uint64_t cur_in = 0ULL;
  uint64_t cur_out = 0ULL;

  asm volatile(
      ::[a] "g"(a), [x] "g"(x), [size_a] "g"(size_a)
      : "cc", "memory", "x9");
  return DigitArrayComputedSize(size_result, result);
#else
  return DigitArrayMult(size_a, a, size_a, a, size_result, result);
#endif
}

// a*= x.  a must have size_a + 1 positions available.
int DigitArrayMultBy(int capacity_a, int size_a, uint64_t* a, uint64_t x) {

  asm volatile(
      ::[a] "g"(a), [x] "g"(x), [size_a] "g"(size_a)
      : "cc", "memory", "x9");

  return DigitArrayComputedSize(size_a, a);
}

// a+= b.
int DigitArrayAddTo(int capacity_a, int size_a, uint64_t* a, int size_b,
                    uint64_t* b) {
  int64_t len_a = (int64_t)size_a;
  int64_t len_b = (int64_t)size_b;

  asm volatile(
      ::[a] "g"(a), [b] "g"(b), [len_a] "g"(len_a), [len_b] "g"(len_b)
      : "cc", "memory", "x9");

  return DigitArrayComputedSize(capacity_a, a);
}

// a-= b
int DigitArraySubFrom(int capacity_a, int size_a, uint64_t* a, int size_b,
                      uint64_t* b) {
  if (size_a < size_b)
    return -1;

  int64_t len_a = (int64_t)size_a;
  int64_t len_b = (int64_t)size_b;

  asm volatile(
      ::[a] "g"(a), [b] "g"(b), [len_a] "g"(len_a), [len_b] "g"(len_b)
      : "cc", "memory", "x9");

  return DigitArrayComputedSize(capacity_a, a);
}

bool DigitArrayShortDivisionAlgorithm(int size_a, uint64_t* a, uint64_t b,
                                      int* size_q, uint64_t* q, uint64_t* r) {
  int64_t len_a = (int64_t)size_a;
  uint64_t* a_high = a + size_a - 1;
  uint64_t* q_high = q + size_a - 1;

  // a/b = q rem r
  asm volatile(
      ::[r] "g"(r), [len_a] "g"(len_a), [a_high] "g"(a_high), [b] "g"(b),
        [q_high] "g"(q_high)
      : "cc", "memory", "x9");

  *size_q = DigitArrayComputedSize(*size_q, q);
  return true;
}
