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
// File: bignum.h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <memory>
#include <iostream>

#include "cryptotypes.h"

#ifndef _CRYPTO_BIGNUM_H__
#define _CRYPTO_BIGNUM_H__

using std::string;

//  num= value_[0]+ 2^64 value_[1] + ... + 2^(64n) value_[n]
class BigNum {
 public:
  bool sign_;  // true: negative
  __attribute__((aligned(4))) int capacity_;
  __attribute__((aligned(4))) int size_;
  __attribute__((aligned(8))) uint64_t* value_;

  BigNum(int size);
  BigNum(BigNum& n);
  BigNum(BigNum& n, int capacity);
  BigNum(int size, uint64_t);  // BigNum with one initialized digit
  ~BigNum();

  int Capacity();  // total number of digits (64 bits) allocated
  int Size();      // number of digit required to hold current value
  uint64_t* ValuePtr();

  bool IsPositive();
  bool IsZero();
  bool IsOne();
  bool IsNegative();
  void ToggleSign();
  void Normalize();
  void ZeroNum();
  bool CopyFrom(BigNum&);
  bool CopyTo(BigNum&);
};

// Support functions
void TempPrintNum(int size_a, uint64_t* a);
int DigitArrayComputedSize(int size_a, uint64_t* a);
bool DigitArrayIsZero(int size_a, uint64_t* a);
void DigitArrayZeroNum(int size_a, uint64_t* a);
bool DigitArrayCopy(int size_a, uint64_t* a, int size_b, uint64_t* b);
int DigitArrayShiftUp(int size_a, uint64_t* a, int shift, int size_r, uint64_t* r);
int DigitArrayShiftDown(int size_a, uint64_t* a, int shift, int size_r, uint64_t* r);
int DigitArrayCompare(int size_a, uint64_t* a, int size_b, uint64_t* b);
int HighBitInDigit(uint64_t a);
int shift_to_top_bit(uint64_t a);
bool DigitArrayDivisionAlgorithm(int size_a, uint64_t* a, int size_b,
                                 uint64_t* b, int* size_q, uint64_t* q,
                                 int* size_r, uint64_t* r);
bool DigitArrayConvertToDecimal(int size_a, uint64_t* a, int* size_s, char* s);
bool DigitArrayConvertToHex(int size_a, uint64_t* a, int* size_s, char* s);
int DigitArrayConvertFromHex(const char* s, int size_a, uint64_t* a);
int DigitArrayConvertFromDecimal(const char* s, int size_a, uint64_t* a);
int DigitArrayAdd(int size_a, uint64_t* a, int size_b, uint64_t* b,
                  int size_result, uint64_t* result);
int DigitArraySub(int size_a, uint64_t* a, int size_b, uint64_t* b,
                  int size_result, uint64_t* result);
void EstimateQuotient(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t b1,
                      uint64_t b2, uint64_t* est);
void Uint64AddStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry);
void Uint64MultStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry);
void Uint64DivStep(uint64_t a, uint64_t b, uint64_t c, uint64_t* result,
                   uint64_t* carry);
void Uint64AddWithCarryStep(uint64_t a, uint64_t b, uint64_t carry_in,
                            uint64_t* result, uint64_t* carry_out);
void Uint64SubWithBorrowStep(uint64_t a, uint64_t b, uint64_t borrow_in,
                             uint64_t* result, uint64_t* borrow_out);
void Uint64MultWithCarryStep(uint64_t a, uint64_t b, uint64_t carry1,
                             uint64_t carry2, uint64_t* result,
                             uint64_t* carry_out);
int DigitArrayMult(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_result, uint64_t* result);
int DigitArraySquare(int size_a, uint64_t* a, int size_result,
                     uint64_t* result);
int DigitArrayMultBy(int capacity_a, int size_a, uint64_t* a, uint64_t x);
int DigitArrayAddTo(int capacity_a, int size_a, uint64_t* a, int size_b,
                    uint64_t* b);
int DigitArraySubFrom(int capacity_a, int size_a, uint64_t* a, int size_b,
                      uint64_t* b);
bool DigitArrayShortDivisionAlgorithm(int size_a, uint64_t* a, uint64_t b,
                                      int* size_q, uint64_t* q, uint64_t* r);


// returns  1, if l>r
// returns  0, if l==r
// returns -1, if l<r
int BigCompare(BigNum& l, BigNum& r);

string* BigConvertToDecimal(BigNum& a);
BigNum* BigConvertFromDecimal(const char* in);
string* BigConvertToHex(BigNum& a);
BigNum* BigConvertFromHex(const char* in);

void PrintNumToLog(BigNum& n, uint64_t base);
void PrintNumToConsole(BigNum& n, uint64_t base);

int BigHighDigit(BigNum& a);              // 0 means all digits 0
int BigHighBit(BigNum& a);                // 0 means all bits 0
bool BigBitPositionOn(BigNum& a, int n);  // position 1 is lowest
int BigMaxPowerOfTwoDividing(BigNum& a);  // 0 means bottom bit is 1

// positive shift increases value
bool BigShift(BigNum& a, int64_t shift, BigNum& r);

bool BigUnsignedAdd(BigNum& a, BigNum& b, BigNum& r);
bool BigUnsignedSub(BigNum& a, BigNum& b, BigNum& r);
bool BigUnsignedMult(BigNum& a, BigNum& b, BigNum& r);
bool BigUnsignedEuclid(BigNum& a, BigNum& b, BigNum& q, BigNum& r);
bool BigUnsignedDiv(BigNum& a, BigNum& b, BigNum& q);
bool BigUnsignedSquare(BigNum& a, BigNum& r);

bool BigUnsignedAddTo(BigNum& a, BigNum& b);
bool BigUnsignedSubFrom(BigNum& a, BigNum& b);
bool BigUnsignedInc(BigNum& a);
bool BigUnsignedDec(BigNum& a);

bool BigAdd(BigNum& a, BigNum& b, BigNum& r);
bool BigSub(BigNum& a, BigNum& b, BigNum& r);
bool BigMult(BigNum& a, BigNum& b, BigNum& r);
bool BigDiv(BigNum& a, BigNum& b, BigNum& r);
bool BigSquare(BigNum& a, BigNum& r);
bool BigUnsignedEuclid(BigNum& a, BigNum& b, BigNum& q, BigNum& r);

bool BigMod(BigNum& a, BigNum& m, BigNum& r);
bool BigModNormalize(BigNum& a, BigNum& m);
bool BigModAdd(BigNum& a, BigNum& b, BigNum& m, BigNum& r);
bool BigModSub(BigNum& a, BigNum& b, BigNum& m, BigNum& r);
bool BigModNeg(BigNum& a, BigNum& m, BigNum& r);
bool BigModMult(BigNum& a, BigNum& b, BigNum& m, BigNum& r);
bool BigModSquare(BigNum& a, BigNum& m, BigNum& r);
bool BigModInv(BigNum& a, BigNum& m, BigNum& r);
bool BigModDiv(BigNum& a, BigNum& b, BigNum& m, BigNum& r);
bool BigModExp(BigNum& b, BigNum& e, BigNum& m, BigNum& r);

bool BigMakeMont(BigNum& a, int r, BigNum& p, BigNum& mont_a);
bool BigMontReduce(BigNum& a, int r, BigNum& m, BigNum& m_prime, BigNum& out);
bool BigMontParams(BigNum& m, int r, BigNum& m_prime);
bool BigMontMult(BigNum& aR, BigNum& bR, BigNum& m, uint64_t r, BigNum& m_prime,
                 BigNum& abR);
bool BigMontExp(BigNum& b, BigNum& e, int r, BigNum& m, BigNum& m_prime,
                BigNum& out);

bool BigExtendedGCD(BigNum& a, BigNum& b, BigNum& x, BigNum& y, BigNum& g);
bool BigCRT(BigNum& s1, BigNum& s2, BigNum& m1, BigNum& m2, BigNum& r);
bool BigGenPrime(BigNum& p, uint64_t num_bits);
bool BigIsPrime(BigNum& n);
bool BigMillerRabin(BigNum& n, BigNum** a, int trys = 20);
bool BigModIsSquare(BigNum& n, BigNum& p);
bool BigModSquareRoot(BigNum& n, BigNum& p, BigNum& r);
bool BigModTonelliShanks(BigNum& n, BigNum& p, BigNum& s);

extern BigNum Big_Zero;
extern BigNum Big_One;
extern BigNum Big_Two;
extern BigNum Big_Three;
extern BigNum Big_Four;
extern BigNum Big_Five;

#endif
