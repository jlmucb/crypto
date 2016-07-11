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

// estimate quotient (cf: Knuth v2)
// *est-2<= q <= *est
// note b1>0 and (a1 a2)_b >= b1_b, b= 2^64
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

  asm volatile(
      "\tmovq   %[est], %%rcx\n"
      "\tmovq   %[n1], %%rdx\n"
      "\tmovq   %[n2], %%rax\n"
      "\tdivq   %[d1]\n"
      "\tmovq   %%rax, (%%rcx)\n" 
      ::[est] "g"(est), [n1] "g"(n1), [n2] "g"(n2), [d1] "g"(d1)
      : "cc", "memory", "%rax", "%rcx", "%rdx");
}

//  carry:result= a+b
void Uint64AddStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry) {
  asm volatile(
      "\tmovq   %[result], %%rcx\n"
      "\tmovq   %[carry], %%rdx\n"
      "\tmovq   $0,(%%rdx)\n"
      "\tmovq   %[a], %%rax\n"
      "\taddq   %[b], %%rax\n"
      "\tmovq   %%rax, (%%rcx)\n"
      "\tjnc    1f\n"
      "\tmovq   $1,(%%rdx)\n"
      "1:\n"
      ::[result] "g"(result), [carry] "g"(carry), [a] "g"(a), [b] "g"(b)
      : "cc", "memory", "%rax", "%rcx", "%rdx");
}

//  result= a-b, borrow
void Uint64SubStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t* borrow) {
}

//  carry:result= a*b
//  mulq   op:    rdx:rax= %rax*op
void Uint64MultStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry) {
  asm volatile(
      "\tmovq   %[result], %%rcx\n"
      "\tmovq   %[carry], %%rbx\n"
      "\tmovq   %[a], %%rax\n"
      "\tmulq   %[b]\n"
      "\tmovq   %%rax, (%%rcx)\n"
      "\tmovq   %%rdx,(%%rbx)\n"
      "1:\n" ::[result] "g"(result),
      [carry] "g"(carry), [a] "g"(a), [b] "g"(b)
      : "cc", "memory", "%rax", "%rbx", "%rcx", "%rdx");
}

//  q= a:b/c remainder, r
// divq:  op1: rdx:rax
//         rdx:rem
//         rax: result
void Uint64DivStep(uint64_t a, uint64_t b, uint64_t c, uint64_t* result,
                   uint64_t* carry) {
  asm volatile(
      "\tmovq   %[result], %%rcx\n"
      "\tmovq   %[carry], %%rbx\n"
      "\tmovq   %[a], %%rdx\n"
      "\tmovq   %[b], %%rax\n"
      "\tdivq   %[c]\n"
      "\tmovq   %%rax, (%%rcx)\n"
      "\tmovq   %%rdx,(%%rbx)\n"
      "1:\n"
      ::[result] "m"(result), [carry] "m"(carry),
        [a] "m"(a), [b] "m"(b), [c] "m"(c)
      : "cc", "memory", "%rax", "%rbx", "%rcx", "%rdx");
}

//  carry_out:result= a+b+carry_in
void Uint64AddWithCarryStep(uint64_t a, uint64_t b, uint64_t carry_in,
                            uint64_t* result, uint64_t* carry_out) {
  asm volatile(
      "\tmovq   %[result], %%rcx\n"
      "\tmovq   %[carry_out], %%rbx\n"
      "\tmovq   $0,(%%rbx)\n"
      "\tmovq   %[a], %%rax\n"
      "\taddq   %[b], %%rax\n"
      "\tjnc    1f\n"
      "\tmovq   $1,(%%rbx)\n"
      "1:\n"
      "\taddq    %[carry_in], %%rax\n"
      "\tjnc    2f\n"
      "\tmovq   $1,(%%rbx)\n"
      "2:\n"
      "\tmovq   %%rax, (%%rcx)\n"
      ::[result] "g"(result), [carry_out] "g"(carry_out), [a] "g"(a),
      [b] "g"(b), [carry_in] "g"(carry_in)
      : "cc", "memory", "%rax", "%rbx", "%rcx", "%rdx");
}

//  carry_out:result= a-b-borrow_in if a>b+borrow_in, borrow_out=0
void Uint64SubWithBorrowStep(uint64_t a, uint64_t b, uint64_t borrow_in,
                             uint64_t* result, uint64_t* borrow_out) {
  asm volatile(
      "\tmovq   %[result], %%rcx\n"
      "\tmovq   %[borrow_out], %%rbx\n"
      "\tmovq   $0, (%%rbx)\n"
      "\tmovq   %[a], %%rax\n"
      "\tsubq   %[b],%%rax\n"
      "\tjnc    1f\n"
      "\tmovq   $1,(%%rbx)\n"
      "1:\n"
      "\tsubq   %[borrow_in],%%rax\n"
      "\tjnc    2f\n"
      "\tmovq   $1,(%%rbx)\n"
      "2:\n"
      "\tmovq   %%rax,(%%rcx)\n"
      ::[result] "g"(result), [borrow_out] "g"(borrow_out), [a] "g"(a),
      [b] "g"(b), [borrow_in] "g"(borrow_in)
      : "cc", "memory", "%rax", "%rbx", "%rcx");
}

//  carry_out:result= a*b+carry1+carry2
void Uint64MultWithCarryStep(uint64_t a, uint64_t b, uint64_t carry1,
                             uint64_t carry2, uint64_t* result,
                             uint64_t* carry_out) {
  asm volatile(
      "\tmovq   %[result], %%rcx\n"
      "\tmovq   %[carry_out], %%rbx\n"
      "\tmovq   %[a], %%rax\n"
      "\tmulq   %[b]\n"
      "\taddq   %[carry1], %%rax\n"
      "\tjnc    1f\n"
      "\taddq   $1,%%rdx\n"
      "1:\n"
      "\taddq   %[carry2],%%rax\n"
      "\tjnc    2f\n"
      "\taddq   $1,%%rdx\n"
      "2:\n"
      "\tmovq   %%rax,(%%rcx)\n"
      "\tmovq   %%rdx,(%%rbx)\n"
      ::[a] "g"(a), [b] "g"(b), [carry1] "g"(carry1), [carry2] "g"(carry2),
      [result] "g"(result), [carry_out] "g"(carry_out)
      : "cc", "memory", "%rax", "%rbx", "%rcx", "%rdx");
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

#define FASTMULT
// result = a*b.  returns size of result.  Error if <0
int DigitArrayMult(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_result, uint64_t* result) {
  // output is size_a+size_b or size_a+size_b-1 uint64_t elements
  if ((size_a + size_b) > size_result) {
    LOG(ERROR) << "DigitArrayMult: result is too small\n";
    return -1;
  }
  DigitArrayZeroNum(size_result, result);

#ifdef FASTMULT
  uint64_t carry = 0;
  uint64_t size_A = (uint64_t)size_a;
  uint64_t size_B = (uint64_t)size_b;

  //  Caller ensures out is large enough
  //    r8 : current op1 location
  //    r9 : current op2 location
  //    r11: in1 index
  //    r12: in2 index
  //    r13: current output index
  //    r14: carry
  //    r15: current out location
  asm volatile(
      "\tmovq   %[in1], %%r8\n"
      "\tmovq   %[in2], %%r9\n"
      "\tmovq   %[result], %%r15\n"
      "\txorq   %%r11, %%r11\n"
      "\txorq   %%r14, %%r14\n"

      // outer mult loop
      "1:\n"
      "\txorq   %%r12, %%r12\n"
      "\tmovq   %%r11, %%r13\n"

      // inner mult loop
      "2:\n"
      "\tmovq   (%%r8, %%r11, 8), %%rax\n"
      "\tmulq   (%%r9, %%r12, 8)\n"
      "\taddq   %%r14, %%rax\n"
      "\tadcq   $0, %%rdx\n"
      "\taddq   (%%r15, %%r13, 8), %%rax\n"
      "\tadcq   $0, %%rdx\n"
      "\tmovq   %%rax, (%%r15, %%r13, 8)\n"
      "\tmovq   %%rdx, %%r14\n"
      "\taddq   $1, %%r12\n"
      "\taddq   $1, %%r13\n"
      "\tcmpq   %[size_B], %%r12\n"
      "\tjl     2b\n"

      "\tmovq   %%r14, (%%r15, %%r13, 8)\n"
      "\txorq   %%r14, %%r14\n"
      "\naddq   $1, %%r11\n"
      "\tcmpq   %[size_A], %%r11\n"
      "\tjl     1b\n"
      ::[carry] "m"(carry), [in1] "g"(a), [in2] "g"(b), [size_A] "g"(size_A),
	[size_B] "g"(size_B), [result] "g"(result)
      : "memory", "cc", "%rax", "%rdx", "%r8", "%r9", "%r11", "%r12", "%r13",
        "%r14", "%r15");
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

#define FASTSQUARE
// result = a*a.  returns size of result.  Error if <0
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
      "\tmovq   %[result], %%r15\n"  // %%r15 <-- address of output place
      "\tmovq   %[a], %%r8\n"        // %%r8 <-- address of low input digit
      "\txorq   %%rax,%%rax\n"
      "\tmovl   %[size_a], %%eax\n"  // number of output words
      "\tmovq   %%rax, %%r12\n"      // number of output words
      "\tshlq   $3, %%r12\n"
      "\taddq   %%r8, %%r12\n"  // %%r12>address of last input digit

      // a[i]*a[i]
      "1:\n"
      "\tmovq   (%%r8), %%rax\n"
      "\tmulq   (%%r8)\n"  // a[i]**2 result in rdx:rax
      "\tmovq   %%rax, (%%r15)\n"
      "\tmovq   %%rdx, 8(%%r15)\n"
      "\taddq   $16, %%r15\n"
      "\taddq   $8, %%r8\n"
      "\tcmpq   %%r8, %%r12\n"
      "\tjg     1b\n"

      "\tmovq   %[a], %%r9\n"       // input
      "\tmovq   %%r9, %[cur_in]\n"  // input
      "\tsubq   $8, %[cur_in]\n"
      "\tmovq   %[result], %%r9\n"
      "\tmovq   %%r9, %[cur_out]\n"
      "\tsubq   $8, %[cur_out]\n"

      "\t.balign 16\n"
      "2:\n"
      "\tmovq   %[cur_in], %%r8\n"
      "\taddq   $8, %%r8\n"
      "\tmovq   %%r8, %[cur_in]\n"
      "\tmovq   %[cur_out], %%r15\n"
      "\taddq   $16, %%r15\n"
      "\tmovq   %%r15, %[cur_out]\n"
      "\tmovq   %%r8, %%r9\n"
      "\taddq   $8, %%r9\n"
      "\tcmpq   %%r9, %%r12\n"
      "\tjle    11f\n"

      // loop on %%r9
      "3:\n"
      "\tmovq   (%%r8), %%rax\n"
      "\tmulq   (%%r9)\n"
      "\tmovq   %%r15, %%r11\n"

      // shift by 1, top bit in %%r14
      "\txorq   %%r14, %%r14\n"
      "\tshlq   $1, %%rax\n"
      "\tjnc    4f\n"
      "\tmovq   $1, %%r14\n"

      "4:\n"
      "\tshlq   $1,%%rdx\n"
      "\tjnc    8f\n"
      "\torq    %%r14, %%rdx\n"
      "\txorq   %%r14,%%r14\n"
      "\taddq   $24, %%r11\n"
      "\taddq   %%rax, (%%r15)\n"
      "\tadcq   %%rdx, 8(%%r15)\n"
      "\tadcq   $1, 16(%%r15)\n"
      "\tjnc    10f\n"
      "\tjmp    9f\n"

      "8:\n"
      "\torq    %%r14, %%rdx\n"
      "\txorq   %%r14,%%r14\n"
      "\taddq   $16, %%r11\n"
      "\taddq   %%rax, (%%r15)\n"
      "\tadcq   %%rdx, 8(%%r15)\n"
      "\tjnc    10f\n"

      "9:\n"
      "\taddq   $1, (%%r11)\n"
      "\tjnc    10f\n"
      "\taddq   $8, %%r11\n"
      "\tjmp    9b\n"

      "10:\n"
      "\taddq   $8, %%r9\n"
      "\taddq   $8, %%r15\n"
      "\tcmpq   %%r9, %%r12\n"
      "\tjg     3b\n"
      "\tjmp    2b\n"
      "\t.balign 16\n"
      "11:\n"
      : [cur_in] "=m"(cur_in), [cur_out] "=m"(cur_out)
      : [a] "m"(a), [result] "m"(result), [size_a] "m"(size_a),
        [size_result] "m"(size_result)
      : "memory", "cc", "%rax", "%rdx", "%r8", "%r9", "%r12", "%r11", "%r14",
        "%r15");
  return DigitArrayComputedSize(size_result, result);
#else
  return DigitArrayMult(size_a, a, size_a, a, size_result, result);
#endif
}

// a*= x.  a must have size_a+1 positions available
int DigitArrayMultBy(int capacity_a, int size_a, uint64_t* a, uint64_t x) {
  asm volatile(
      "\txorq   %%r8, %%r8\n"  // carry
      "\txorq   %%rdx, %%rdx\n"
      "\txorq   %%rbx, %%rbx\n"     // clear ctr
      "\tmovl   %[size_a],%%ebx\n"  // ctr
      "\tmovq   %[a], %%rcx\n"
      "\t.balign  16\n"
      "1:\n"
      "\tmovq   (%%rcx), %%rax\n"
#if 1
      "\tmovq   %[x], %%r9\n"
      "\tmulq   %%r9\n"
#else
      // OSX has a problem with this.
      "\tmulq   %[x]\n"
#endif
      "\taddq   %%r8,%%rax\n"
      "\tmovq   $0, %%r8\n"
      "\tjnc    2f\n"
      "\tmovq   $1,%%r8\n"
      "\t.balign  16\n"
      "\t2:\n"
      "\taddq   %%rdx,%%r8\n"
      "\tmovq   %%rax,(%%rcx)\n"
      "\taddq   $8,%%rcx\n"
      "\tsubq   $1,%%rbx\n"
      "\tcmpq   $0,%%rbx\n"
      "\tjg     1b\n"
      "\tmovq   %%r8,(%%rcx)\n"
      ::[a] "g"(a), [x] "g"(x), [size_a] "g"(size_a)
      : "cc", "memory", "%rax", "%rbx", "%rcx", "%rdx", "%r8", "%r9");

  return DigitArrayComputedSize(size_a, a);
}

// a+= b
int DigitArrayAddTo(int capacity_a, int size_a, uint64_t* a, int size_b,
                    uint64_t* b) {
  int64_t len_a = (int64_t)size_a;
  int64_t len_b = (int64_t)size_b;

  asm volatile(
      "\tmovq   %[len_b],%%r9\n"  // ctr
      "\txorq   %%r12, %%r12\n"   // old carry
      "\tmovq   %[b], %%rbx\n"    // b
      "\tmovq   %[a], %%rcx\n"    // a
      "1:\n"
      "\txorq   %%r8, %%r8\n"  // new carry
      "\tmovq   (%%rbx),%%rax\n"
      "\taddq   %%rax,(%%rcx)\n"
      "\tjnc    2f\n"
      "\tmovq   $1,%%r8\n"
      "2:\n"
      "\taddq   %%r12,(%%rcx)\n"
      "\tjnc    3f\n"
      "\tmovq   $1,%%r8\n"
      "3:\n"
      "\tmovq   %%r8,%%r12\n"
      "\taddq   $8,%%rbx\n"
      "\taddq   $8,%%rcx\n"
      "\tsubq   $1,%%r9\n"
      "\tcmpq   $0,%%r9\n"
      "\tjg     1b\n"
      "\tmovq   %[len_a], %%r9\n"
      "\tsubq   %[len_b],%%r9\n"
      "\t3:\n"
      "\txorq   %%r8, %%r8\n"  // new carry
      "\tmovq   (%%rbx),%%rax\n"
      "\taddq   %%r12,(%%rcx)\n"
      "\tjnc    5f\n"
      "\tmovq   $1,%%r8\n"
      "5:\n"
      "\tmovq   %%r8,%%r12\n"
      "\taddq   $8,%%rbx\n"
      "\taddq   $8,%%rcx\n"
      "\tsubq   $1,%%r9\n"
      "\tcmpq   $0,%%r9\n"
      "\tjg     3b\n"
      "7:\n"
      "\tmovq   %%r8,(%%rcx)\n"
      ::[a] "g"(a), [b] "g"(b), [len_a] "g"(len_a), [len_b] "g"(len_b)
      : "cc", "memory", "%rax", "%rbx", "%rcx", "%rdx", "%r8", "%r9", "%r12");

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
      "\tmovq   %[len_b],%%r9\n"  // ctr
      "\txorq   %%r12, %%r12\n"   // old borrow
      "\tmovq   %[b], %%rbx\n"    // b
      "\tmovq   %[a], %%rcx\n"    // a
      "1:\n"
      "\txorq   %%r8, %%r8\n"  // new borrow
      "\tmovq   (%%rbx),%%rax\n"
      "\tsubq   %%rax,(%%rcx)\n"
      "\tjnc    2f\n"
      "\tmovq   $1,%%r8\n"
      "2:\n"
      "\tsubq   %%r12,(%%rcx)\n"
      "\tjnc    5f\n"
      "\tmovq   $1,%%r8\n"
      "5:\n"
      "\tmovq   %%r8,%%r12\n"
      "\taddq   $8,%%rbx\n"
      "\taddq   $8,%%rcx\n"
      "\tsubq   $1,%%r9\n"
      "\tcmpq   $0,%%r9\n"
      "\tjg     1b\n"
      "\tmovq   %[len_a], %%r9\n"
      "\tsubq   %[len_b],%%r9\n"
      "\t3:\n"
      "\tsubq   %%r12,(%%rcx)\n"
      "\tjnc    6f\n"
      "\tmovq   $1,%%r8\n"
      "6:\n"
      "\tmovq   %%r8,%%r12\n"
      "\taddq   $8,%%rbx\n"
      "\taddq   $8,%%rcx\n"
      "\tsubq   $1,%%r9\n"
      "\tcmpq   $0,%%r9\n"
      "\tjg     3b\n"
      ::[a] "g"(a), [b] "g"(b), [len_a] "g"(len_a), [len_b] "g"(len_b)
      : "cc", "memory", "%rax", "%rbx", "%rcx", "%rdx", "%r8", "%r9", "%r12");

  return DigitArrayComputedSize(capacity_a, a);
}

bool DigitArrayShortDivisionAlgorithm(int size_a, uint64_t* a, uint64_t b,
                                      int* size_q, uint64_t* q, uint64_t* r) {
  int64_t len_a = (int64_t)size_a;
  uint64_t* a_high = a + size_a - 1;
  uint64_t* q_high = q + size_a - 1;

  asm volatile(
      "\txorq   %%rdx, %%rdx\n"
      "\tmovq   %[len_a], %%r8\n"
      "\tmovq   %[a_high], %%rbx\n"
      "\tmovq   %[q_high], %%rcx\n"
      "\t1:\n"
      "\tmovq   (%%rbx), %%rax\n"
      "\tdivq   %[b]\n"
      "\tmovq   %%rax, (%%rcx)\n"
      "\tsubq   $8, %%rbx\n"
      "\tsubq   $8, %%rcx\n"
      "\tsubq   $1, %%r8\n"
      "\tcmpq   $0, %%r8\n"
      "\tjg     1b\n"
      "\tmovq   %[r],%%rbx\n"
      "\tmovq   %%rdx, (%%rbx)\n"
      ::[r] "g"(r), [len_a] "g"(len_a), [a_high] "g"(a_high), [b] "g"(b),
        [q_high] "g"(q_high)
      : "cc", "memory", "%rax", "%rbx", "%rcx", "%rdx", "%r8");
  *size_q = DigitArrayComputedSize(*size_q, q);
  return true;
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
