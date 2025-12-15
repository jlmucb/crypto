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
// File: gf2_common.h

#ifndef _GF2_COMMON_H__
#define _GF2_COMMON_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <string>

#include "splitsecret.pb.h"


using namespace std;

#ifndef byte_t
typedef unsigned char byte_t;
#endif

class gf2_8 {
public:
  byte_t v_[8];
};
extern bool g_inverse_initialized;
extern gf2_8 g_gf2_inverse[256];

class gf2_instance {
public:
  gf2_8 a_[48];
  gf2_8 y_;
};

gf2_8* get_inverse(gf2_8& d);
int max(int a, int b);
int real_size(int size_in, byte_t* in);
bool gf2_mult(int size_in1, byte_t* in1, int size_in2, byte_t* in2,
              int size_min_poly, byte_t* min_poly, int* size_out, byte_t* out);
bool gf2_add(int size_in1, byte_t* in1, int size_in2, byte_t* in2,
             int size_min_poly, byte* min_poly, int* size_out, byte* out);
bool gf2_reduce(int size_min_poly, byte_t* min_poly,
                int* size_in_out, byte_t* in_out);
void print_poly(int size_in, byte_t* in);
bool to_internal_representation(uint16_t in, int* size_out, byte_t* out);
bool from_internal_representation( int size_in, byte_t* in, uint16_t* out);
bool init_inverses(int size_min_poly, byte_t* min_poly);
void byte_8_zero(byte_t* a);
void byte_16_zero(byte_t* a);
void gf2_8_zero(gf2_8& a);
bool byte_8_equal(byte_t* a, byte_t* b);
bool gf2_8_equal(gf2_8& a, gf2_8& b);
void byte_8_copy(byte_t* a, byte_t* b);
void gf2_8_copy(gf2_8& a, gf2_8& b);

bool get_random_byte(bool non_zero, byte_t* y);

bool multiply_linear(int n, int size_min_poly, byte_t* min_poly, gf2_8* a, gf2_8* x, gf2_8& y);
bool gaussian_solve(int n, int size_min_poly, byte_t* min_poly, gf2_instance* a, gf2_8* x);

bool divide_equation_by(int n, int size_min_poly, byte_t* min_poly, int pivot_col,
                        gf2_instance& row);
bool subtract_equation_by(int n, int size_min_poly, byte_t* min_poly, int pivot_col,
                          gf2_instance& row_subtracted, gf2_instance& row);
void print_vector(int n, gf2_8* row);
void print_array(int n, gf2_8* a);
void print_row(int n, gf2_instance& row);
void print_matrix(int n, int* perm, gf2_instance* a);
bool generate_invertible_matrix(int n, int size_min_poly, byte_t* min_poly,
        gf2_8* a);
bool fill_shard(string& secretname, int number_of_sequences, int sequence_number, int shards_outstanding,
                int shards_required, int shard_number, int num_equations, int num_coefficients,
                gf2_instance* instance, split_secret_message* shard);
void print_shard(split_secret_message& msg);

#endif

