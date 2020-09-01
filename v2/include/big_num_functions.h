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

#ifndef _BIG_NUM_FUNCTIONS__
#define _BIG_NUM_FUNCTIONS__

int big_compare(big_num& l, big_num& r);
int big_high_digit(big_num& a);
bool big_bit_position_on(big_num& a, int n);
int big_max_power_of_two_dividing(big_num& a);
bool big_shift(big_num& a, int64_t shift, big_num& r);
bool big_unsigned_add(big_num& a, big_num& b, big_num& r);
bool big_unsigned_sub(big_num& a, big_num& b, big_num& r);
bool big_unsigned_mult(big_num& a, big_num& b, big_num& r);
bool big_unsigned_euclid(big_num& a, big_num& b, big_num& q, big_num& r);
bool big_unsigned_div(big_num& a, big_num& b, big_num& q);
bool big_unsigned_square(big_num& a, big_num& r);
bool big_unsigned_add_to(big_num& a, big_num& b);
bool big_unsigned_sub_from(big_num& a, big_num& b);
bool big_unsigned_inc(big_num& a);
bool big_unsigned_dec(big_num& a);
bool big_add(big_num& a, big_num& b, big_num& r);
bool big_sub(big_num& a, big_num& b, big_num& r);
bool big_mult(big_num& a, big_num& b, big_num& r);
bool big_div(big_num& a, big_num& b, big_num& r);
bool big_square(big_num& a, big_num& r);
bool convert_to_decimal(int size_a, uint64_t* n, string* s);
big_num* big_convert_from_decimal(string& s);
bool big_convert_to_hex(big_num& a, string* hex);
big_num* big_convert_from_hex(const char* in);

bool big_extended_gcd(big_num& a, big_num& b, big_num& x, big_num& y, big_num& g);
bool big_crt(big_num& s1, big_num& s2, big_num& m1, big_num& m2, big_num& r);
bool big_mod(big_num& a, big_num& m, big_num& r);
bool big_mod_add(big_num& a, big_num& b, big_num& m, big_num& r);
bool big_mod_neg(big_num& a, big_num& m, big_num& r);
bool big_mod_neg(big_num& a, big_num& m, big_num& r);
bool big_mod_mult(big_num& a, big_num& b, big_num& m, big_num& r);
bool big_mod_square(big_num& a, big_num& m, big_num& r);
bool big_mod_div(big_num& a, big_num& b, big_num& m, big_num& r);
bool big_mod_exp(big_num& a, big_num& e, big_num& m, big_num& r);
bool big_gen_prime(big_num& p, uint64_t num_bits, int prime_trys=2500);
int big_high_bit(big_num& a);
bool big_miller_rabin(big_num& n, big_num** random_a, int trys);
bool big_is_prime(big_num& n);
bool big_mod_is_square(big_num& n, big_num& p);
bool big_mod_tonelli_shanks(big_num& a, big_num& p, big_num& s);
bool big_mod_square_root(big_num& n, big_num& p, big_num& r);
bool big_make_mont(big_num& a, int r, big_num& m, big_num& mont_a);
bool big_mont_params(big_num& m, int r, big_num& m_prime);
bool big_mont_reduce(big_num& a, int r, big_num& m, big_num& m_prime, big_num& mont_a);
bool big_mont_mult(big_num& aR, big_num& bR, big_num& m, uint64_t r, big_num& m_prime,
                 big_num& abR);
bool big_mont_exp(big_num& b, big_num& e, int r, big_num& m, big_num& m_prime, big_num& out);
bool big_mod_normalize(big_num& a, big_num& m);

#endif
