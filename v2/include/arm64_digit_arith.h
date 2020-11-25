// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: arm64_digit_arith.h


#include "crypto_support.h"

#ifndef _INTEL_DIGIT_ARITH_H__
#define _INTEL_DIGIT_ARITH_H__

int digit_array_real_size(int size_a, uint64_t* a);
void digit_array_print(int size_a, uint64_t* a);
bool digit_array_is_zero(int size_a, uint64_t* a);
void digit_array_zero_num(int size_a, uint64_t* a);
bool digit_array_copy(int size_a, uint64_t* a, int size_b, uint64_t* b);
int digit_array_shift_up(int size_a, uint64_t* a, int shift, int size_r, uint64_t* r);
int digit_array_shift_down(int size_a, uint64_t* a, int shift, int size_r, uint64_t* r);
int digit_array_compare(int size_a, uint64_t* a, int size_b, uint64_t* b);
int high_bit_in_digit(uint64_t a);
int shift_to_top_bit(uint64_t a);
void u64_add_step(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry);
void u64_mult_step(uint64_t a, uint64_t b, uint64_t* result, uint64_t* carry);
void u64_div_step(uint64_t a, uint64_t b, uint64_t c, uint64_t* result, uint64_t* carry);
void u64_add_with_carry_step(uint64_t a, uint64_t b, uint64_t carry_in,
                            uint64_t* result, uint64_t* carry_out);
void u64_sub_with_borrow_step(uint64_t a, uint64_t b, uint64_t borrow_in,
                             uint64_t* result, uint64_t* borrow_out);
void u64_product_step(uint64_t a, uint64_t b, uint64_t carry1,
                             uint64_t carry2, uint64_t* result, uint64_t* carry_out);
int digit_array_add(int size_a, uint64_t* a, int size_b, uint64_t* b,
                  int size_result, uint64_t* result);
int digit_array_sub(int size_a, uint64_t* a, int size_b, uint64_t* b,
                    int size_result, uint64_t* result);
int digit_array_add_to(int capacity_a, int size_a, uint64_t* a, int size_b,
                    uint64_t* b);
int digit_array_sub_from(int capacity_a, int size_a, uint64_t* a, int size_b, uint64_t* b);
int digit_array_mult(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_result, uint64_t* result);
int digit_array_square(int size_a, uint64_t* a, int size_result, uint64_t* result);
int digit_array_mult_by(int capacity_a, int size_a, uint64_t* a, uint64_t x);
bool digit_array_short_division_algorithm(int size_a, uint64_t* a, uint64_t b,
                                      int* size_q, uint64_t* q, uint64_t* r);
void estimate_quotient(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t b1,
                       uint64_t b2, uint64_t* est);
bool digit_array_division_algorithm(int size_a, uint64_t* a, int size_b,
       uint64_t* b, int* size_q, uint64_t* q, int* size_r, uint64_t* r);
bool digit_convert_to_decimal(int size_a, uint64_t* n, string* s);
bool digit_convert_from_decimal(string& s, int size_n, uint64_t* n);
#endif
