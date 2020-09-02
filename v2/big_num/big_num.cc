//
// copy_right 2014 John Manferdelli, All Rights Reserved.
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
// File: big_num.cc

#include "crypto_support.h"
#include "big_num.h"
#include "intel_digit_arith.h"

//  num= value_[0]+ 2^64 value_[1] + ... + 2^(64n) value_[n]
//  bool      sign_;  // true: negative
//  __declspec(align(4)) uint32_t  capacity_;
//  __declspec(align(4)) uint32_t  size_;
//  __declspec(align(8)) uint64_t* value_;

big_num::big_num(int size) {
  value_ = new uint64_t[size];
  capacity_ = size;
  digit_array_zero_num(capacity_, value_);
  size_ = 1;
  sign_ = false;
}

big_num::big_num(int size, uint64_t x) {
  value_ = new uint64_t[size];
  capacity_ = size;
  size_ = 1;
  digit_array_zero_num(capacity_, value_);
  value_[0] = x;
  sign_ = false;
}

big_num::big_num(big_num& n, int capacity) {
  capacity_ = capacity;
  size_ = n.size_;
  sign_ = n.sign_;
  value_ = new uint64_t[capacity_];
  copy_from(n);
}

big_num::big_num(big_num& n) {
  capacity_ = n.capacity_;
  size_ = n.size_;
  sign_ = n.sign_;
  value_ = new uint64_t[capacity_];
  copy_from(n);
}

big_num::~big_num() {
  if (value_ != nullptr) {
    digit_array_zero_num(capacity_, value_);
    delete value_;
    value_ = nullptr;
  }
}

int big_num::capacity() { return capacity_; }

int big_num::size() { return size_; }

uint64_t* big_num::value_ptr() { return value_; }

bool big_num::is_positive() { return !sign_; }

bool big_num::is_zero() {
  size_ = digit_array_real_size(capacity_, value_);
  if (size_ == 1 && value_[0] == 0ULL)
    return true;
  return false;
}

bool big_num::is_one() {
  size_ = digit_array_real_size(capacity_, value_);
  if (size_ == 1 && value_[0] == 1ULL)
    return true;
  return false;
}

bool big_num::is_negative() { return sign_; }

void big_num::toggle_sign() { sign_ = !sign_; }

void big_num::normalize() {
  if (is_zero()) {
    size_ = 1;
    sign_ = false;
    return;
  }
  size_ = digit_array_real_size(capacity_, value_);
}

void big_num::zero_num() {
  size_ = 1;
  sign_ = false;
  digit_array_zero_num(capacity_, value_);
}

bool big_num::copy_from(big_num& old) {
  if (old.size_ > capacity_)
    return false;
  digit_array_zero_num(capacity_, value_);
  sign_ = old.sign_;
  if (!digit_array_copy(old.size_, old.value_, capacity_, value_))
    return false;
  size_ = digit_array_real_size(capacity_, value_);
  return true;
}

bool big_num::copy_to(big_num& other) {
  if (size_ > other.capacity_)
    return false;
  digit_array_zero_num(other.capacity_, other.value_);
  other.sign_ = sign_;
  if (!digit_array_copy(size_, value_, other.capacity_, other.value_))
    return false;
  other.size_ = digit_array_real_size(other.capacity_, other.value_);
  return true;
}
