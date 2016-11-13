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

#ifndef byte
typedef unsigned char byte;
#endif

class gf2_8 {
public:
  byte v_[8];
};
extern bool g_inverse_initialized;
extern gf2_8 g_gf2_inverse[256];

int max(int a, int b);
int real_size(int size_in, byte* in);
bool gf2_mult(int size_in1, byte* in1, int size_in2, byte* in2,
              int size_min_poly, byte* min_poly, int* size_out, byte* out);
bool gf2_add(int size_in1, byte* in1, int size_in2, byte* in2,
             int size_min_poly, byte* min_poly, int* size_out, byte* out);
bool gf2_reduce(int size_min_poly, byte* min_poly,
                int* size_in_out, byte* in_out);
void print_poly(int size_in, byte* in);
bool to_internal_representation(uint16_t in, int* size_out, byte* out);
bool from_internal_representation( int size_in, byte* in, uint16_t* out);
bool init_inverses(int size_min_poly, byte* min_poly);

#endif

