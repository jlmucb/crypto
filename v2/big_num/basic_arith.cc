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
// File: basic_arith.cc for bignums

#include "crypto_support.h"
#include "big_num.h"
#include "intel64_arith.h"

// returns  1, if l>r
// returns  0, if l==r
// returns -1, if l<r
int big_compare(big_num& l, big_num& r) {
  if (l.is_positive() && r.is_negative())
    return 1;
  if (r.is_positive() && r.is_negative())
    return -1;
  if (l.is_positive() && r.is_positive())
    return digit_array_compare(l.Size(), l.ValuePtr(), r.Size(), r.ValuePtr());
  return 1 - digit_array_compare(l.Size(), l.ValuePtr(), r.Size(), r.ValuePtr());
}

int big_high_digit(big_num& a) {
  a.normalize();
  if (a.size_ == 1) {
    if (a.value_[0] != 0)
      return 1;
    else
      return 0;
  }
  return a.size_;
}

int big_high_bit(big_num& a) {
  return NBITSINUINT64 * (a.size_ - 1) + high_bitInDigit(a.value_[a.size_ - 1]);
}

bool big_bit_position_on(big_num& a, int n) {
  int j = (n - 1) / NBITSINUINT64;
  int k = n - j * NBITSINUINT64 - 1;

  if (a.size_ < (j + 1))
    return false;
  uint64_t x = a.value_[j];
  if ((x >> k) & 1)
    return true;
  return false;
}

int big_max_power_of_two_dividing(big_num& a) {
  int i, j;
  uint64_t n = 0;
  uint64_t x;
  bool getout = false;

  for (i = 0; i < a.size_; i++) {
    x = a.value_[i];
    for (j = 0; j < NBITSINUINT64; j++) {
      if ((x & 1ULL) != 0) {
        getout = true;
        break;
      }
      n++;
      x >>= 1;
    }
    if (getout)
      break;
  }
  return n;
}

bool big_shift(big_num& a, int64_t shift, big_num& r) {
  int k;

  // positive shift increases value
  if (shift > 0) {
    k = digit_array_shift_up(a.size_, a.value_, (int)shift, r.capacity_, r.value_);
    if (k < 0)
      return false;
    r.size_ = k;
    return true;
  } else if (shift == 0LL) {
    return r.CopyFrom(a);
  } else {
    k = digit_array_shift_down(a.size_, a.value_, (int)-shift, r.capacity_,
                            r.value_);
    if (k < 0)
      return false;
    r.size_ = k;
    return true;
  }
}

bool big_unsigned_add(big_num& a, big_num& b, big_num& r) {
  int k = digit_array_add(a.size_, a.value_, b.size_, b.value_, r.capacity_,
                        r.value_);
  if (k < 0)
    return false;
  r.size_ = k;
  return true;
}

bool big_unsigned_sub(big_num& a, big_num& b, big_num& r) {
  int k = digit_array_sub(a.size_, a.value_, b.size_, b.value_, r.capacity_,
                        r.value_);
  if (k < 0)
    return false;
  r.size_ = k;
  r.normalize();
  return true;
}

bool big_unsigned_mult(big_num& a, big_num& b, big_num& r) {
  int k = digit_array_mult(a.size_, a.value_, b.size_, b.value_, r.capacity_,
                         r.value_);
  if (k < 0) {
    return false;
  }
  r.size_ = k;
  r.normalize();
  return true;
}

bool big_unsigned_Euclid(big_num& a, big_num& b, big_num& q, big_num& r) {
  int size_q = q.capacity_;
  int size_r = r.capacity_;
  if (!digit_array_divisionAlgorithm(a.size_, a.value_, b.size_, b.value_,
                                   &size_q, q.value_, &size_r, r.value_)) {
    return false;
  }
  q.size_ = digit_array_ComputedSize(size_q, q.value_);
  r.size_ = digit_array_ComputedSize(size_r, r.value_);
  if (r.size_ > b.size_) {
    r.ZeroNum();
    return false;
  }
  return true;
}

bool big_unsigned_div(big_num& a, big_num& b, big_num& q) {
  big_num tmp(2 * a.capacity_ + 1);
  return big_unsigned_Euclid(a, b, q, tmp);
}

bool big_unsigned_square(big_num& a, big_num& r) {
  int k = digit_array_square(a.size_, a.value_, r.capacity_, r.value_);
  if (k < 0)
    return false;
  r.size_ = k;
  return true;
}

bool big_unsigned_addTo(big_num& a, big_num& b) {
  int k = digit_array_addTo(a.capacity_, a.size_, a.value_, b.size_, b.value_);
  if (k < 0)
    return false;
  a.size_ = k;
  return true;
}

bool big_unsigned_subFrom(big_num& a, big_num& b) {
  int k = digit_array_subFrom(a.capacity_, a.size_, a.value_, b.size_, b.value_);
  if (k < 0)
    return false;
  a.size_ = k;
  return true;
}

bool big_unsigned_Inc(big_num& a) {
  uint64_t one = 1ULL;
  int k = digit_array_addTo(a.size_, a.size_, a.value_, 1, &one);
  if (k < 0)
    return false;
  return true;
}

bool big_unsigned_Dec(big_num& a) {
  uint64_t one = 1ULL;
  int k = digit_array_subFrom(a.size_, a.size_, a.value_, 1, &one);
  if (k < 0)
    return false;
  return true;
}

bool big_add(big_num& a, big_num& b, big_num& r) {
  if (a.is_positive() && b.is_positive()) {
    if (!big_unsigned_add(a, b, r))
      return false;
    r.sign_ = false;
    r.normalize();
    return true;
  } else if (a.is_negative() && b.IsNegative()) {
    if (!big_unsigned_add(a, b, r)) return false;
    r.sign_ = true;
    r.normalize();
    return true;
  } else if (a.is_positive() && b.is_negative()) {
    int cmp = digit_array_compare(a.size_, a.value_, b.size_, b.value_);
    if (cmp > 0) {
      r.sign_ = false;
      return big_unsigned_sub(a, b, r);
    }
    if (cmp == 0) {
      r.ZeroNum();
      return true;
    }
    r.sign_ = true;
    return big_unsigned_sub(b, a, r);
  } else {  // a<0, b>0
    int cmp = digit_array_compare(b.size_, b.value_, a.size_, a.value_);
    if (cmp > 0) {
      r.sign_ = false;
      return big_unsigned_sub(b, a, r);
    }
    if (cmp == 0) {
      r.ZeroNum();
      return true;
    }
    r.sign_ = true;
    return big_unsigned_sub(a, b, r);
  }
}

bool big_sub(big_num& a, big_num& b, big_num& r) {
  if (a.is_positive() && b.is_negative()) {
    if (!big_unsigned_add(a, b, r))
      return false;
    r.sign_ = false;
    return true;
  } else if (a.is_negative() && b.is_positive()) {
    if (!big_unsigned_add(a, b, r)) return false;
    r.sign_ = true;
    return true;
  } else if (a.is_positive() && b.is_positive()) {
    int cmp = digit_array_compare(a.size_, a.value_, b.size_, b.value_);
    if (cmp > 0) {
      r.sign_ = false;
      return big_unsigned_sub(a, b, r);
    }
    if (cmp == 0) {
      r.ZeroNum();
      return true;
    }
    r.sign_ = true;
    return big_unsigned_sub(b, a, r);
  } else {  // a<0, b<0
    int cmp = digit_array_compare(b.size_, b.value_, a.size_, a.value_);
    if (cmp > 0) {
      r.sign_ = true;
      return big_unsigned_sub(b, a, r);
    }
    if (cmp == 0) {
      r.ZeroNum();
      return true;
    }
    r.sign_ = false;
    return big_unsigned_sub(a, b, r);
  }
}

bool big_mult(big_num& a, big_num& b, big_num& r) {
  if (a.is_positive() != b.is_positive())
    r.sign_ = true;
  return big_unsigned_mult(a, b, r);
}

bool big_div(big_num& a, big_num& b, big_num& r) {
  if (a.is_positive() != b.is_positive())
    r.sign_ = true;
  return big_unsigned_div(a, b, r);
}

bool big_square(big_num& a, big_num& r) {
  return big_unsigned_square(a, r);
}

string* big_ConvertToDecimal(big_num& a) {
  int k = 32 * a.size_;
  char* str = new char[k];

  if (!digit_array_ConvertToDecimal(a.size_, a.value_, &k, str)) {
    if (str != nullptr) {
      delete []str;
      str = nullptr;
    }
    return nullptr;
  }
  string* s = new string(str);
  if (str != nullptr) {
    delete []str;
    str = nullptr;
  }
  return s;
}

big_num* big_ConvertFromDecimal(const char* in) {
  int k = strlen(in);
  int m = ((k + 29) / 30) + 6;
  big_num* n = new big_num(m);
  n->size_ = digit_array_ConvertFromDecimal(in, n->capacity_, n->value_);
  return n;
}

string* big_ConvertToHex(big_num& a) {
  int k = 18 * a.size_;
  char* str = new char[k];

  if (!digit_array_ConvertToHex(a.size_, a.value_, &k, str)) {
    if (str != nullptr) {
      delete []str;
      str = nullptr;
    }
    return nullptr;
  }
  string* s = new string(str);
  if (str != nullptr) {
    delete []str;
    str = nullptr;
  }
  return s;
}

big_num* big_ConvertFromHex(const char* in) {
  int k = strlen(in);
  int m = ((k + 31) / 16) + 1;
  big_num* n = new big_num(m);

  n->size_ = digit_array_ConvertFromHex(in, n->capacity_, n->value_);
  if (n->size_ < 0) {
    delete n;
    return nullptr;
  }
  return n;
}
