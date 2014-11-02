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
// File: bignum.cc

#include "cryptotypes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "bignum.h"
#include "intel64_arith.h"

//  num= value_[0]+ 2^64 value_[1] + ... + 2^(64n) value_[n]
//  bool      sign_;  // true: negative
//  __declspec(align(4)) uint32_t  capacity_;
//  __declspec(align(4)) uint32_t  size_;
//  __declspec(align(8)) uint64_t* value_;
  
BigNum::BigNum(int size) {
  value_= new uint64_t[size];
  capacity_= size; 
  DigitArrayZeroNum(capacity_, value_);
  size_= 1; 
  sign_= false;
}

BigNum::BigNum(int size, uint64_t x) {
  value_= new uint64_t[1];
  capacity_= 1;
  size_= 1; 
  value_[0]= x;
  sign_= false;
}


BigNum::BigNum(BigNum& n) {
  capacity_= n.capacity_; 
  size_= n.size_; 
  sign_= n.sign_; 
  value_= new uint64_t[capacity_];
  CopyFrom(n);
}

BigNum::~BigNum() {
  if(value_!=NULL) {
    DigitArrayZeroNum(capacity_, value_);
    delete value_;
    value_= NULL;
  }
}

int BigNum::Capacity() {
  return capacity_;
}

int BigNum::Size() {
  return size_;
}

uint64_t*   BigNum::ValuePtr() {
  return value_;
}

bool BigNum::IsPositive() {
  return !sign_;
}

bool BigNum::IsZero() {
  size_= DigitArrayComputedSize(capacity_, value_);
  if(size_==1 && value_[0]==0ULL)
    return true;
  return false; 
}

bool BigNum::IsOne() {
  size_= DigitArrayComputedSize(capacity_, value_);
  if(size_==1 && value_[0]==1ULL)
    return true;
  return false; 
}

bool BigNum::IsNegative() {
  return sign_;
}

void BigNum::ToggleSign() {
  sign_= !sign_;
}

void BigNum::Normalize() {
  if(IsZero()) {
    size_= 1;
    sign_= false;
    return;
  }
  size_= DigitArrayComputedSize(capacity_, value_);
}

void BigNum::ZeroNum() {
  size_= 1;
  sign_= false;
  DigitArrayZeroNum(capacity_, value_);
}

bool BigNum::CopyFrom(BigNum& old) {
  if(old.size_>capacity_)
    return false; 
  DigitArrayZeroNum(capacity_, value_);
  sign_= old.sign_;
  if(!DigitArrayCopy(old.size_, old.value_, capacity_, value_))
    return false;
  size_= DigitArrayComputedSize(capacity_, value_);
  return true;
}

bool BigNum::CopyTo(BigNum& other) {
  if(size_>other.capacity_)
    return false; 
  DigitArrayZeroNum(other.capacity_, other.value_);
  other.sign_= sign_;
  if(!DigitArrayCopy(size_, value_, other.capacity_, other.value_))
    return false;
  other.size_= DigitArrayComputedSize(other.capacity_, other.value_);
  return true;
}

