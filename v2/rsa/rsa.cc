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
// File: rsa.cc

#include "crypto_support.h"
#include "big_num.h"
#include "rsa.h"
#include "big_num_functions.h"

rsa::rsa() {
  initialized_ = true;
  bit_size_modulus_ = 0;
  m_ = nullptr;
  e_ = nullptr;
  d_ = nullptr;
  p_ = nullptr;
  q_ = nullptr;
  dp_ = nullptr;
  dq_ = nullptr;
  m_prime_ = nullptr;
  p_prime_ = nullptr;
  q_prime_ = nullptr;
  rsa_key_ = nullptr;
}

rsa::~rsa() {
  initialized_ = false;
  bit_size_modulus_ = 0;
  if (rsa_key_ != nullptr) {
    delete rsa_key_;
    rsa_key_ = nullptr;
  }
  if (m_ != nullptr) {
    m_->zero_num();
    delete m_;
    m_ = nullptr;
  }
  if (e_ != nullptr) {
    e_->zero_num();
    delete e_;
    e_ = nullptr;
  }
  if (d_ != nullptr) {
    d_->zero_num();
    delete d_;
    d_ = nullptr;
  }
  if (p_ != nullptr) {
    p_->zero_num();
    delete p_;
    p_ = nullptr;
  }
  if (q_ != nullptr) {
    q_->zero_num();
    delete q_;
    q_ = nullptr;
  }
  if (dp_ != nullptr) {
    dp_->zero_num();
    delete dp_;
    dp_ = nullptr;
  }
  if (dq_ != nullptr) {
    dq_->zero_num();
    delete dq_;
    dq_ = nullptr;
  }
  if (q_prime_ != nullptr) {
    q_prime_->zero_num();
    delete q_prime_;
    q_prime_ = nullptr;
  }
  if (m_prime_ != nullptr) {
    m_prime_->zero_num();
    delete m_prime_;
    m_prime_ = nullptr;
  }
  if (p_prime_ != nullptr) {
    p_prime_->zero_num();
    delete p_prime_;
    p_prime_ = nullptr;
  }
}

bool rsa::get_serialized_key_message(string* s) {
  if (rsa_key_ == nullptr)
    return false;
  if (!rsa_key_->SerializeToString(s))
    return false;
  return true;
}

bool rsa::extract_key_message_from_serialized(string& s) {
  if (rsa_key_ == nullptr)
    return false;
  if (!rsa_key_->ParseFromString(s))
    return false;
  if (!retrieve_parameters_from_key_message())
    return false;
  return true;
}

bool rsa::compute_fast_decrypt_parameters() {
#if 0
  if (m_ == nullptr) {
    return false;
  }
  big_num t(2 * m_->capacity_ + 1);
  big_num y(2 * m_->capacity_ + 1);
  big_num g(2 * m_->capacity_ + 1);
  big_num p_minus_1(2 * p_->capacity_ + 1);
  big_num q_minus_1(2 * q_->capacity_ + 1);

  if (!big_sub(*p_, big_one, p_minus_1)) {
    return false;
  }
  if (!big_sub(*q_, big_one, q_minus_1)) {
    return false;
  }
  if (!big_mult(p_minus_1, q_minus_1, t)) {
    return false;
  }
  if (!big_extended_gcd(t, *e_, y, *d_, g)) {
    return false;
  }
  if (!big_mod_normalize(*d_, t)) {
    return false;
  }
  t.zero_num();
  y.zero_num();
  if (!big_extended_gcd(p_minus_1, *e_, y, *dp_, g)) {
    return false;
  }
  if (!big_mod_normalize(*dp_, p_minus_1)) {
    return false;
  }
  t.zero_num();
  y.zero_num();
  if (!big_extended_gcd(q_minus_1, *e_, y, *dq_, g)) {
    return false;
  }
  if (!big_mod_normalize(*dq_, q_minus_1)) {
    return false;
  }
  r_ = big_high_bit(*m_);
  if (!big_montParams(*m_, r_, *m_prime_)) {
    return false;
  }
  int r = big_high_bit(*p_);
  if (!big_montParams(*p_, r, *p_prime_)) {
    return false;
  }
  r = big_high_bit(*q_);
  if (!big_montParams(*q_, r, *q_prime_)) {
    return false;
  }
#endif
  return true;
}

bool rsa::retrieve_parameters_from_key_message() {
  // int bytes_to_u64_array(string& b, int size_n, uint64_t* n);
  return true;
}

bool rsa::set_parameters_in_key_message() {
  return true;
}

bool rsa::generate_rsa(int num_bits) {
  bit_size_modulus_ = num_bits;

  m_ = new big_num(1 + 2 * num_bits / NBITSINUINT64);
  p_ = new big_num(1 + num_bits / NBITSINUINT64);
  q_ = new big_num(1 + num_bits / NBITSINUINT64);
  e_ = new big_num(1, 0x010001ULL);

  if (!big_gen_prime(*p_, num_bits / 2)) {
    return false;
  }
  if (!big_gen_prime(*q_, num_bits / 2)) {
    return false;
  }
  if (!big_mult(*p_, *q_, *m_)) {
    return false;
  }
  // compute d_, and the others
  if (!compute_fast_decrypt_parameters()) {
    return false;
  }
  return true;
}

bool rsa::make_rsa_key(const char* name, const char* purpose, double secondstolive) {
  bool success = true;
  string not_before;
  string not_after;
  string p, q, m, e, d, dp, dq;
  string m_prime, p_prime, q_prime;

  time_point t_now;

  if (!t_now.time_now())
    return false;
  time_point t_expire;
  t_expire.add_interval_to_time(t_now, secondstolive);

  if (!t_now.encodeTime(&not_before))
    return false;

  if (!t_expire.encodeTime(&not_after))
    return false;
  not_before_.assign(not_before);
  not_after_.assign(not_after);

  if (m_ != nullptr) {
    if (u64_array_to_bytes(m_->size(), m_->value_ptr(), &m) < 0) {
      success = false;
      goto done;
    }
  }
  if (e_ != nullptr) {
    if (u64_array_to_bytes(e_->size(), e_->value_ptr(), &e) < 0) {
      success = false;
      goto done;
    }
  }
  if (p_ != nullptr) {
    if (u64_array_to_bytes(p_->size(), p_->value_ptr(), &p) < 0) {
      success = false;
      goto done;
    }
  }
  if (q_ != nullptr) {
    if (u64_array_to_bytes(q_->size(), q_->value_ptr(), &q) < 0) {
      success = false;
      goto done;
    }
  }
  if (d_ != nullptr) {
    if (u64_array_to_bytes(d_->size(), d_->value_ptr(), &d) < 0) {
      success = false;
      goto done;
    }
  }

  rsa_key_ = make_rsakey("rsa", name, bit_size_modulus_,
    purpose, not_before.c_str(), not_after.c_str(), m, e,
    d, p, q, dp, dq, m_prime,
    p_prime, q_prime);
  if (rsa_key_ == nullptr)
    return false;

done:
  return success;
}

bool rsa::encrypt(int size_in, byte* in, int* size_out, byte* out,
                     int speed) {
#if 0
  int bytes_in_block = bit_size_modulus_ / NBITSINBYTE;

  if (size_in > bytes_in_block) {
    return false;
  }

  int new_byte_size = (size_in + bytes_in_block - 1) / bytes_in_block;
  new_byte_size *= bytes_in_block;
  big_num int_in(1 + 4 * new_byte_size / sizeof(uint64_t));
  big_num int_inp(1 + 4 * new_byte_size / sizeof(uint64_t));
  big_num int_inq(1 + 4 * new_byte_size / sizeof(uint64_t));
  big_num int_out(1 + 4 * new_byte_size / sizeof(uint64_t));
  big_num int_outp(1 + 4 * new_byte_size / sizeof(uint64_t));
  big_num int_outq(1 + 4 * new_byte_size / sizeof(uint64_t));

  // ReverseCpy(new_byte_size, in, (byte*)int_in.value_);
  int_in.normalize();
  if (speed == 0) {
    if (!big_mod_exp(int_in, *e_, *m_, int_out)) {
      return false;
    }
  } else if (speed == 1) {
    if (!big_mont_exp(int_in, *e_, r_, *m_, *m_prime_, int_out)) {
      return false;
    }
  } else if (speed == 2) {
    if (!big_mod(int_in, *p_, int_inp)) {
      return false;
    }
    if (!big_mod(int_in, *q_, int_inq)) {
      return false;
    }
    if (!big_mod_exp(int_inp, *e_, *p_, int_outp)) {
      return false;
    }
    if (!big_mod_exp(int_in, *e_, *q_, int_outq)) {
      return false;
    }
    if (!big_crt(int_outp, int_outq, *p_, *q_, int_out)) {
      return false;
    }
  } else if (speed == 3) {
    if (p_prime_ == nullptr || p_prime_ == nullptr) {
      return false;
    }
    int t = big_high_bit(*p_);
    if (!big_mod(int_in, *p_, int_inp)) {
      return false;
    }
    if (!big_mod(int_in, *q_, int_inq)) {
      return false;
    }
    if (!big_mont_exp(int_inp, *e_, t, *p_, *p_prime_, int_outp)) {
      return false;
    }
    if (!big_mont_exp(int_inq, *e_, t, *q_, *q_prime_, int_outq)) {
      return false;
    }
    if (!big_crt(int_outp, int_outq, *p_, *q_, int_out)) {
      return false;
    }
  } else {
    return false;
  }
  // ReverseCpy(new_byte_size, (byte*)int_out.value_, out);
  *size_out = new_byte_size;
#endif
  return true;
}

bool rsa::decrypt(int size_in, byte* in, int* size_out, byte* out,
                     int speed) {
#if 0
  int bytes_in_block = bit_size_modulus_ / NBITSINBYTE;

  if (size_in > bytes_in_block) {
    return false;
  }
  int new_byte_size = (size_in + bytes_in_block - 1) / bytes_in_block;
  new_byte_size *= bytes_in_block;

  big_num int_in(1 + 4 * new_byte_size / sizeof(uint64_t));
  big_num int_inp(1 + 4 * new_byte_size / sizeof(uint64_t));
  big_num int_inq(1 + 4 * new_byte_size / sizeof(uint64_t));
  big_num int_out(1 + 4 * new_byte_size / sizeof(uint64_t));
  big_num int_outp(1 + 4 * new_byte_size / sizeof(uint64_t));
  big_num int_outq(1 + 4 * new_byte_size / sizeof(uint64_t));

  //ReverseCpy(new_byte_size, in, (byte*)int_in.value_);
  int_in.normalize();
  if (speed == 0) {
    if (!big_mod_exp(int_in, *d_, *m_, int_out)) {
      return false;
    }
  } else if (speed == 1) {
    if (!big_mont_exp(int_in, *d_, r_, *m_, *m_prime_, int_out)) {
      return false;
    }
  } else if (speed == 2) {
    if (!big_mod(int_in, *p_, int_inp)) {
      return false;
    }
    if (!big_mod_exp(int_inp, *dp_, *p_, int_outp)) {
      return false;
    }
    if (!big_mod_exp(int_inq, *dq_, *q_, int_outq)) {
      return false;
    }
    if (!big_crt(int_outp, int_outq, *p_, *q_, int_out)) {
      return false;
    }
  } else if (speed == 3) {
    if (p_prime_ == nullptr || p_prime_ == nullptr) {
      return false;
    }
    int t = big_high_bit(*p_);
    if (!big_mod(int_in, *p_, int_inp)) {
      return false;
    }
    if (!big_mod(int_in, *q_, int_inq)) {
      return false;
    }
    if (!big_mont_exp(int_inp, *dp_, t, *p_, *p_prime_, int_outp)) {
      return false;
    }
    if (!big_mont_exp(int_inq, *dq_, t, *q_, *q_prime_, int_outq)) {
      return false;
    }
    if (!big_crt(int_outp, int_outq, *p_, *q_, int_out)) {
      return false;
    }
  } else {
    return false;
  }
  // ReverseCpy(new_byte_size, (byte*)int_out.value_, (byte*)out);
  *size_out = new_byte_size;
#endif
  return true;
}
