//
// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: bignum.h


#include "crypto_support.h"

#ifndef _CRYPTO_BIG_NUM_H__
#define _CRYPTO_BIG_NUM_H__

//  num= value_[0]+ 2^64 value_[1] + ... + 2^(64n) value_[n]
class big_num {
 public:
  bool sign_;  // true: negative
  __attribute__((aligned(4))) int capacity_;
  __attribute__((aligned(4))) int size_;
  __attribute__((aligned(8))) uint64_t* value_;

  big_num(int size);
  big_num(big_num& n);
  big_num(big_num& n, int capacity);
  big_num(int size, uint64_t);  // big_num with one initialized digit
  ~big_num();

  int capacity();  // total number of digits (64 bits) allocated
  int size();      // number of digit required to hold current value
  uint64_t* value_ptr();

  bool is_positive();
  bool is_zero();
  bool is_one();
  bool is_negative();
  void toggle_sign();
  void normalize();
  void zero_num();
  bool copy_from(big_num&);
  bool copy_to(big_num&);
};

extern int num_smallest_primes;
extern uint64_t smallest_primes[];
extern big_num big_zero;
extern big_num big_one;
extern big_num big_two;
extern big_num big_three;
extern big_num big_four;
extern big_num big_five;

int big_num_get_random(int num_bytes, byte* buf);
bool init_big_num();
void close_big_num();

#endif
