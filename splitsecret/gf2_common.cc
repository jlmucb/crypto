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

gf2_8* get_inverse(gf2_8& d) {
  uint16_t u;
  if (!from_internal_representation(8, d.v_, &u))
    return nullptr;
  return &g_gf2_inverse[u];
}


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
  for (int i = k; i < *size_out; i++)
    out[i] = 0;
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

void byte_8_copy(byte* a, byte* b) {
  for (int i = 0; i < 8; i++) 
    b[i] = a[i];
}

void gf2_8_copy(gf2_8& a, gf2_8& b) {
  byte_8_copy(a.v_, b.v_);
}

void byte_8_zero(byte* a) {
  for (int i = 0; i < 8; i++)
    a[i] = 0;
}

void gf2_8_zero(gf2_8& a) {
    byte_8_zero(a.v_);
}

void byte_16_zero(byte* a) {
  for (int i = 0; i < 16; i++)
    a[i] = 0;
}

bool init_inverses(int size_min_poly, byte* min_poly) {
  for (int j = 0; j < 256; j++) {
    gf2_8_zero(g_gf2_inverse[j]);
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
    byte_16_zero(a);
    to_internal_representation(x, &size_a, a);
    for (uint16_t y = 2; y < 256; y++) {
      size_b = 16;
      byte_16_zero(b);
      for (int i = 0; i < 32; i++) c[i] = 0;
      to_internal_representation(y, &size_b, b);
      size_c = 16;
      gf2_mult(size_a, a, size_b, b, size_min_poly, min_poly, &size_c, c);
      // g_gf2_inverse[1] is 1
      if (byte_8_equal(c, g_gf2_inverse[1].v_)) {
        uint16_t z;
        from_internal_representation(size_b, b, &z);
        byte_8_copy(b, g_gf2_inverse[x].v_);
        byte_8_copy(a, g_gf2_inverse[z].v_);
        break;
      }
    }
  }
  g_inverse_initialized = true;
  return true;
}

bool multiply_linear(int n, int size_min_poly, byte* min_poly, gf2_8* a, gf2_8* x, gf2_8& y) {
printf("multiply_linear, n: %d, a: ", n);print_poly(8, a->v_); printf(", x: "); print_poly(8, x->v_); printf("\n");
  gf2_8_zero(y);
  int size_t1 = 16;
  byte t1[16];
  int size_t2 = 16;
  byte t2[16];

  for (int i = 0; i < n; i++) {
    size_t1 = 16;
    byte_16_zero(t1);
    if(!gf2_mult(8, a[i].v_, 8, x[i].v_, size_min_poly, min_poly,
                         &size_t1, t1))
      return false;
    size_t2 = 16;
    byte_16_zero(t2);
    if(!gf2_add(8, t1, 8, y.v_, size_min_poly, min_poly,
                        &size_t2, t2))
      return false;
    byte_8_copy(t2, y.v_);
  }
  return true;
}

void print_row(int n, gf2_instance& row) {
  uint16_t u;
  for (int j = 0; j < n; j++) {
    from_internal_representation(8, row.a_[j].v_, &u);
    printf(" %02x", u);
  }
  from_internal_representation(8, row.y_.v_, &u);
  printf(" =    %02x\n", u);
}

void print_matrix(int n, int* perm, gf2_instance* a) {
  for (int i = 0; i < n; i++) {
    print_row(n, a[perm[i]]);
  }
}

bool isZero(gf2_8& x) {
  for (int i = 0; i < 8; i++) {
    if (x.v_[i] != 0)
      return false;
  }
  return true;
}

int find_non_zero(int n, int col, int* perm, gf2_instance* row) {
  for (int j = col; j < n; j++) {
    if (!isZero(row[perm[j]].a_[col]))
      return j;
  }
  return -1;
}

bool divide_equation_by(int n, int size_min_poly, byte* min_poly, int pivot_col,
                        gf2_instance& row) {
  int size_out;
  byte out[32];

  gf2_8* inv = get_inverse(row.a_[pivot_col]);
  if (inv == nullptr)
    return false;
  for (int j = 0; j < n; j++) {
    size_out = 32;
    if(!gf2_mult(8, inv->v_, 8, row.a_[j].v_, size_min_poly, min_poly, &size_out, out))
      return false;
    byte_8_copy(out, row.a_[j].v_);
  }
  size_out = 32;
  if(!gf2_mult(8, inv->v_, 8, row.y_.v_, size_min_poly, min_poly, &size_out, out))
    return false;
  byte_8_copy(out, row.y_.v_);
  return true;
}

bool subtract_equation_by(int n, int size_min_poly, byte* min_poly, int pivot_col,
                          gf2_instance& row_subtracted, gf2_instance& row) {
  int size_out1;
  byte out1[16];
  int size_out2;
  byte out2[16];
  byte pivot[8];
  byte_8_copy(row.a_[pivot_col].v_, pivot);
  for (int j = pivot_col; j < n; j++) {
    size_out1 = 16;
    size_out2 = 16;
    if(!gf2_mult(8, row_subtracted.a_[j].v_, 8, pivot, size_min_poly, min_poly, &size_out1, out1))
      return false;
    if(!gf2_add(8, out1, 8, row.a_[j].v_, size_min_poly, min_poly, &size_out2, out2))
      return false;
    byte_8_copy(out2, row.a_[j].v_);
  }

  size_out1 = 16;
  size_out2 = 16;
  if(!gf2_mult(8, row_subtracted.y_.v_, 8, pivot, size_min_poly, min_poly, &size_out1, out1))
      return false;
  if(!gf2_add(8, out1, 8, row.y_.v_, size_min_poly, min_poly, &size_out2, out2))
    return false;
  byte_8_copy(out2, row.y_.v_);
  return true;
}

// Solve Sum from i = 0 to n-1 a[i] * x[i] = c[i].
// by Gaussian elimination over GF(2^8).
// Output x[i].
bool gaussian_solve(int n, int size_min_poly, byte* min_poly, gf2_instance* a, gf2_8* x) {
  if (!g_inverse_initialized) {
    if (!init_inverses(size_min_poly, min_poly)) {
      printf("Can't compute inverses\n");
      return false;
    }
  }

  // This is the rearranged order of the a matrix which results in an upper triangular form.
  int* permutation = new int[n];
  for (int i = 0; i < n; i++)
    permutation[i] = i;

  int m;

  // Get it into upper triangular form.
  for (int j = 0; j < n; j++) {
    // Find an instance with a non-zero entry in position.
    int k = find_non_zero(n, j, permutation, a);
    if (k < 0) {
      printf("No non zero at %d\n", j);
      delete []permutation;
      return false;
    }

    // Permute current row j with identified row.
    m = permutation[j];
    permutation[j] = permutation[k];
    permutation[k] = m;

    // Divide identified row by leading coefficient.
    if (!divide_equation_by(n, size_min_poly, min_poly, j,
                          a[permutation[j]])) {
        delete []permutation;
        return false;
    }

    // Subtract appropriate multiple of identified row from later rows.
    for (int l = (j+1); l < n; l++) {
      if(!subtract_equation_by(n, size_min_poly, min_poly, j,
                              a[permutation[j]], a[permutation[l]])) {
        delete []permutation;
        return false;
      }
    }
  }
print_matrix(n, permutation, a);

  int size_out1;
  byte out1[16];

  // Reverse solve.
  for (int j = (n - 1); j >= 0; j--) {
    if (isZero(a[j].a_[j])) {
      delete []permutation;
      return false;
    }

    gf2_8 u;
    for (int i = 0; i < 8; i++)
      u.v_[i] = 0;
    if(!multiply_linear(n - j - 1, size_min_poly, min_poly, &a[permutation[j]].a_[j + 1], &x[j + 1], u)) {
      delete []permutation;
      return false;
    }
    size_out1 = 16;
    if(!gf2_add(8, u.v_, 8, a[permutation[j]].y_.v_, size_min_poly, min_poly,
                      &size_out1, out1))
      return false;
    byte_8_copy(out1, x[j].v_);
  }
  delete []permutation;
  return true;
}
