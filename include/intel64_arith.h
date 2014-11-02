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
// File: intel64_arith.h

#include "cryptotypes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "util.h"
#include "bignum.h"

#ifndef _INTEL64_ARITH_H__
#define _INTEL64_ARITH_H__

void    TempPrintNum(int size_a, uint64_t* a);
void    DigitArrayZeroNum(int size_a, uint64_t* a);
bool    DigitArrayIsZero(int size_a, uint64_t* a);
bool    DigitArrayCopy(int size_a, uint64_t* a, int size_b, uint64_t* b);
int     DigitArrayComputedSize(int size_a, uint64_t* a);
int     DigitArrayCompare(int size_a, uint64_t* a, int size_b, uint64_t* b);
int     HighBitInDigit(uint64_t a);
int     DigitArrayShiftUp(int size_a, uint64_t* a, int shift,
                          int size_r, uint64_t* r);
int     DigitArrayShiftDown(int size_a, uint64_t* a, int shift,
                      int size_r, uint64_t* r);
void    EstimateQuotient(uint64_t a1, uint64_t a2, uint64_t a3, 
                         uint64_t b1, uint64_t b2, uint64_t* est);

void    Uint64AddStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry);
void    Uint64SubStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t* borrow);
void    Uint64MultStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry);
void    Uint64DivStep(uint64_t a, uint64_t b, uint64_t c, 
                      uint64_t* result, uint64_t* carry);
void    Uint64AddWithCarryStep(uint64_t a, uint64_t b, uint64_t carry_in, 
                               uint64_t* result, uint64_t* carry_out);
void    Uint64SubWithBorrowStep(uint64_t a, uint64_t b, uint64_t borrow_in, 
                                uint64_t* result, uint64_t* borrow_out);
void    Uint64MultWithCarryStep(uint64_t a, uint64_t b, uint64_t carry1, 
                                uint64_t carry2, uint64_t* result, 
                                uint64_t* carry_out);
int     DigitArrayAdd(int size_a, uint64_t* a, int size_b, uint64_t* b, 
                          int size_result, uint64_t* result);
int     DigitArraySub(int size_a, uint64_t* a, int size_b, uint64_t* b, 
                          int size_result, uint64_t* result);
int     DigitArrayMult(int size_a, uint64_t* a, int size_b, uint64_t* b, 
                       int size_result, uint64_t* result);
int     DigitArraySquare(int size_a, uint64_t* a, int size_result, 
                        uint64_t* result);

int     DigitArrayMultBy(int capacity_a, int size_a, uint64_t* a, uint64_t x);
int     DigitArrayAddTo(int capacity_a, int size_a, uint64_t* a, int size_b, 
                        uint64_t* b);
int     DigitArraySubFrom(int capacity_a, int size_a, uint64_t* a, int size_b,
                          uint64_t* b);

bool    DigitArrayShortDivisionAlgorithm(int size_a, uint64_t* a, uint64_t b,
                                int* size_q, uint64_t* q, uint64_t* r);
bool    DigitArrayDivisionAlgorithm(int size_a, uint64_t* a, int size_b, 
                      uint64_t* b, int* size_q, uint64_t* q, int* size_r, 
                      uint64_t* r);
bool    DigitArrayConvertToDecimal(int size_a, uint64_t* a, int* size_s, char* s);
bool    DigitArrayConvertToHex(int size_a, uint64_t* a, int* size_s, char* s);
int     DigitArrayConvertFromDecimal(const char* s, int size_a, uint64_t* a);
int     DigitArrayConvertFromHex(const char* s, int size_a, uint64_t* a); 
#endif

