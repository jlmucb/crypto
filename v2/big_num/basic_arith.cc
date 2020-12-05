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
// File: basic_arith.cc for bignums

#include "crypto_support.h"
#include "big_num.h"
#include "intel_digit_arith.h"
#include "big_num_functions.h"

// returns  1, if l>r
// returns  0, if l==r
// returns -1, if l<r
int big_compare(big_num& l, big_num& r) {
  if (l.is_positive() && r.is_negative())
    return 1;
  if (r.is_positive() && l.is_negative())
    return -1;
  if (l.is_positive() && r.is_positive())
    return digit_array_compare(l.size(), l.value_ptr(), r.size(), r.value_ptr());
  if (l.is_negative() && r.is_negative())
    return -digit_array_compare(l.size(), l.value_ptr(), r.size(), r.value_ptr());
  return 0;
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
  return NBITSINUINT64 * (a.size_ - 1) + high_bit_in_digit(a.value_[a.size_ - 1]);
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
  int n = 0;
  uint64_t x;

  for (int i = 0; i < a.size_; i++) {
    x = a.value_[i];
    for (int j = 0; j < NBITSINUINT64; j++) {
      if ((x & 1ULL) != 0) {
        return n;
      }
      n++;
      x >>= 1;
    }
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
    return r.copy_from(a);
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
  r.normalize();
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

bool check_big_unsigned_euclid(big_num& a, big_num& b, big_num& q, big_num& r) {
  big_num t1(2 * a.capacity_ + 1);
  big_num t2(2 * a.capacity_ + 1);

  if (!big_unsigned_mult(q, b, t1)) {
    return false;
  }
  if (!big_unsigned_add(t1, r, t2)) {
    return false;
  }
  if ((digit_array_compare(a.size_, a.value_, t2.size_, t2.value_) != 0) ||
      (digit_array_compare(b.size_, b.value_, r.size_, r.value_) < 0)) {
    printf("check_big_unsigned_euclid failed\n");
    printf("a: "); a.print(); printf("\n");
    printf("b: "); b.print(); printf("\n");
    printf("q: "); q.print(); printf("\n");
    printf("r: "); r.print(); printf("\n");
    printf("a*b: "); t1.print(); printf("\n");
    return false;
  }
  return true;
}

bool big_unsigned_euclid(big_num& a, big_num& b, big_num& q, big_num& r) {
  int size_q = q.capacity_;
  int size_r = r.capacity_;
  if (!digit_array_division_algorithm(a.size_, a.value_, b.size_, b.value_,
                  &size_q, q.value_, &size_r, r.value_)) {
    return false;
  }
  q.normalize();
  r.normalize();
  if (r.capacity_ < b.size_) {
    r.zero_num();
    return false;
  }
#if 1
  if (!check_big_unsigned_euclid(a, b, q, r)) {
    printf("a: "); a.print(); printf("\n");
    printf("b: "); b.print(); printf("\n");
    return false;
  }
#endif
  return true;
}

bool big_unsigned_div(big_num& a, big_num& b, big_num& q) {
  big_num tmp(2 * a.capacity_ + 1);
  return big_unsigned_euclid(a, b, q, tmp);
}

bool big_unsigned_square(big_num& a, big_num& r) {
  int k = digit_array_square(a.size_, a.value_, r.capacity_, r.value_);
  if (k < 0)
    return false;
  r.size_ = k;
  return true;
}

bool big_unsigned_add_to(big_num& a, big_num& b) {
  int k = digit_array_add_to(a.capacity_, a.size_, a.value_, b.size_, b.value_);
  if (k < 0)
    return false;
  a.size_ = k;
  return true;
}

bool big_unsigned_sub_from(big_num& a, big_num& b) {
  int k = digit_array_sub_from(a.capacity_, a.size_, a.value_, b.size_, b.value_);
  if (k < 0)
    return false;
  a.size_ = k;
  return true;
}

bool big_unsigned_inc(big_num& a) {
  uint64_t one = 1ULL;
  int k = digit_array_add_to(a.capacity_, a.size_, a.value_, 1, &one);
  if (k < 0)
    return false;
  return true;
}

bool big_unsigned_dec(big_num& a) {
  uint64_t one = 1ULL;
  int k = digit_array_sub_from(a.capacity_, a.size_, a.value_, 1, &one);
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
  } else if (a.is_negative() && b.is_negative()) {
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
      r.zero_num();
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
      r.zero_num();
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
      r.zero_num();
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
      r.zero_num();
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

big_num* big_convert_from_decimal(string& s) {

  int sn = strlen(s.c_str());
  sn = (sn + 2) / 3;  // number of 10 bit number slots needed
  sn *= 10;
  sn = (sn + NBITSINBYTE - 1) / NBITSINBYTE;
  int m = 1 + (sn + sizeof(uint64_t) - 1) / sizeof(uint64_t);

  big_num* n = new big_num(m);
  if (!digit_convert_from_decimal(s, n->capacity_, n->value_ptr())) {
    delete n;
    return nullptr;
  }
  n->normalize();
  return n;
}

bool big_convert_to_hex(big_num& a, string* hex) {
  string b;
  int k = u64_array_to_bytes(a.size_, a.value_ptr(), &b);
  if (k < 0)
    return false;
  if (!bytes_to_hex(b, hex))
    return false;
  return true;
}

big_num* big_convert_from_hex(const char* in) {
  int m = ((((strlen(in) + 1) / 2) + sizeof(uint64_t) - 1) / sizeof(uint64_t)) + 1;

  string h(in);
  string b;
  if (!hex_to_bytes(h, &b))
    return nullptr;
  big_num* n = new big_num(m + 1);
  if (bytes_to_u64_array(b, n->capacity_, n->value_ptr()) < 0) {
    delete n;
    return nullptr;
  }
  n->sign_ = false;
  n->normalize();
  return n;
}
