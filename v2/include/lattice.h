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
// File: lattice.h

#include "crypto_support.h"

#ifndef _CRYPTO_LATTICE_H__
#define _CRYPTO_LATTICE_H__

#include <vector>
using std::vector;

typedef vector<double> real_vector;

inline int matrix_index(int n_rows, int n_cols, int i, int j) {
  return n_cols * i + j;
}

bool vector_alloc(int n, real_vector* v);
bool vector_zero(int n, real_vector* v);
bool vector_add(int n, real_vector& v1,  real_vector& v2, real_vector* v);
bool vector_sub(int n, real_vector& v1,  real_vector& v2, real_vector* v);
bool vector_scalar_mult(int n, const double d,  real_vector& v1, real_vector* v);
bool vector_dot_product(int n, real_vector& v1, real_vector& v2, double* dp);
bool matrix_zero(int n, int m, double* u);

bool gso(int n, real_vector* b, real_vector* b_norm, double* u);
bool size_reduce(int n, real_vector* b, real_vector* b_norm, double* u);
bool lll(int n, real_vector* b);

#endif
