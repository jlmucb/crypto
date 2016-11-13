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
// File: gf2_common.cc

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <string>
#include <iostream>
#include <fstream>
#include <memory>

#include "gf2_common.h"

bool g_inverse_initialized = false;
gf2_8 g_gf2_inverse[256];


int max(int a, int b) {
  if (a > b)
    return a;
  return b;
}

int real_size(int size_in, byte* in) {
  for (int i = (size_in - 1); i > 0; i--) {
    if (in[i] != 0) {
      return i + 1;
    }
  }
  return 1;
}

bool gf2_add(int size_in1, byte* in1, int size_in2, byte* in2,
             int size_min_poly, byte* min_poly, int* size_out, byte* out) {
  int m = max(size_in1, size_in1);

  if (m > *size_out)
    return false;
  int size_big_in;
  byte* big_in;
  int size_small_in;
  byte* small_in;

  if (size_in1 > size_in2) {
    size_big_in = size_in1;
    big_in = in1;
    size_small_in = size_in2;
    small_in = in2;
  } else {
    size_big_in = size_in2;
    big_in = in2;
    size_small_in = size_in1;
    small_in = in1;
  }

  int i;
  for (i = 0; i < size_small_in; i++) {
    out[i] = big_in[i] ^ small_in[i];
  }
  for (; i < size_big_in; i++) {
    out[i] = big_in[i];
  }
  
  *size_out = real_size(size_big_in, out);
  return true;
}

bool gf2_mult(int size_in1, byte* in1, int size_in2, byte* in2,
              int size_min_poly, byte* min_poly, int* size_out, byte* out) {
  int size_out_t = size_in1 + size_in2;
  byte* out_t = new byte[size_out_t];

  for (int i = 0; i < size_out_t; i++)
    out_t[i] = 0;

  for (int i = 0; i < size_in1; i++) {
    for (int j = 0; j < size_in2; j++) {
      out_t[i + j] ^= in1[i] & in2[j];
    }
  }

  if (!gf2_reduce(size_min_poly, min_poly, &size_out_t, out_t)) {
    delete []out_t;
    return false;
  }

  int k = real_size(size_out_t, out_t);
  if (k > *size_out) {
    delete []out_t;
    return false;
  }
  *size_out = k;
  for (int i = 0; i < k; i++) {
    out[i] = out_t[i];
  }
  delete []out_t;
  return true;
}

bool gf2_reduce(int size_min_poly, byte* min_poly,
                int* size_in_out, byte* in_out) {
  int k = real_size(*size_in_out, in_out);
  int n = k;
  while (n >= size_min_poly) {
    int m = n - size_min_poly;
    if (in_out[m + size_min_poly - 1] !=0) {
      for (int i = 0; i < size_min_poly; i++) {
        in_out[m + i] ^= min_poly[i];
      }
    }
    n--;
  }
  *size_in_out = real_size(k, in_out);
  return true;
}

void print_poly(int size_in, byte* in) {
  for (int i = (size_in - 1); i > 0; i--) {
    if (in[i] != 0)
      printf("x^%d + ", i);
  }
  if (in[0] != 0)
    printf("1");
  else
    printf("0");
}

bool to_internal_representation(uint16_t in, int* size_out, byte* out) {
    if (*size_out < 16)
      return false;
    for (int i = 0; i < 16; i++) {
        out[i] = (byte) (in & 1);
        in >>= 1;
    }
    *size_out = real_size(16, out);
    return true;
}

bool from_internal_representation(int size_in, byte* in, uint16_t* out) {
  if (real_size(size_in, in) > 16)
    return false;
  uint16_t t = 1;
  *out = 0;

  for (int i = 0; i < size_in; i++) {
    if (in[i] != 0)
      *out |= t;
    t <<= 1;
  }
  return true;
}

bool byte_8_equal(byte* a, byte* b) {
  for (int i = 0; i < 8; i++) {
      if (a[i] != b[i])
        return false;
  }
  return true;
}


bool gf2_8_equal(gf2_8& a, gf2_8& b) {
  return byte_8_equal(a.v_, b.v_);
}

void gf2_8_copy(byte* a, byte* b) {
  for (int i = 0; i < 8; i++) 
    b[i] = a[i];
}

bool init_inverses(int size_min_poly, byte* min_poly) {
  for (int j = 0; j < 256; j++) {
    for (int i = 0; i < 8; i++)
      g_gf2_inverse[j].v_[i] = 0;
  }
  g_gf2_inverse[1].v_[0] = 1;

  int size_a = 16;
  byte a[16];
  int size_b = 16;
  byte b[16];
  int size_c = 32;
  byte c[32];

  for (uint16_t x = 2; x < 256; x++) {
    // g_gf2_inverse[0] is 0
    if (!gf2_8_equal(g_gf2_inverse[0], g_gf2_inverse[x])) {
      continue;
    }
    size_a = 16;
    for (int i = 0; i < 16; i++) a[i] = 0;
    to_internal_representation(x, &size_a, a);
    for (uint16_t y = 2; y < 256; y++) {
      size_b = 16;
      for (int i = 0; i < 16; i++) b[i] = 0;
      for (int i = 0; i < 32; i++) c[i] = 0;
      to_internal_representation(y, &size_b, b);
      size_c = 16;
      gf2_mult(size_a, a, size_b, b, size_min_poly, min_poly, &size_c, c);
      // g_gf2_inverse[1] is 1
      if (byte_8_equal(c, g_gf2_inverse[1].v_)) {
        uint16_t z;
        from_internal_representation(size_b, b, &z);
        gf2_8_copy(b, g_gf2_inverse[x].v_);
        gf2_8_copy(a, g_gf2_inverse[z].v_);
        break;
      }
    }
  }
  g_inverse_initialized = true;
  return true;
}
