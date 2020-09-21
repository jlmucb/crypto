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
// File: hash.cc

#include "crypto_support.h"
#include "lattice.h"



bool vector_alloc(int n, real_vector* v) {
  real_vector::iterator it;
  it = v->begin();

  v->insert(it, n, 0.0);
  return true;
}

bool vector_zero(int n, real_vector* v) {
  for (int i = 0; i < n; i++) {
    (*v)[i] = 0.0;
  }
  return true;
}

bool vector_dot_product(int n, real_vector& v1, real_vector& v2, double* dp) {
  if (v1.size() != v2.size())
    return false;

  double s = 0.0;
  for (int i = 0; i < n; i++) {
    s += v1[i] * v2[i];
  }
  *dp = s;
  return true;
}


bool vector_add(int n, real_vector& v1,  real_vector& v2, real_vector* v) {
  if (v1.size() != v2.size())
    return false;

  for (int i = 0; i < n; i++)
    (*v)[i] = v1[i] + v2[i];
  return true;
}

bool vector_sub(int n, real_vector& v1,  real_vector& v2, real_vector* v) {
  if (v1.size() != v2.size())
    return false;

  for (int i = 0; i < n; i++)
    (*v)[i] = v1[i] - v2[i];
  return true;
}

bool vector_scalar_mult(int n, const double d,  real_vector& v1, real_vector* v) {
  for (int i = 0; i < n; i++)
    (*v)[i] = d * v1[i];
  return true;
}

bool matrix_zero(int n, int m, double* u) {
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < m; j++) {
      u[matrix_index(n, m, i, j)] = 0.0;
    }
  }
  return true;
}

bool gso(int n, real_vector* b, real_vector* b_norm, double* u) {
  double d = 0.0;
  double t = 0.0;
  matrix_zero(n, n, u);
  real_vector temp;
  vector_alloc(n, &temp);

  b_norm[0] = b[0];
  u[matrix_index(n, n, 0, 0)] = 1.0;

  for (int i = 1; i < n; i++) {
      b_norm[i] = b[i];
    for (int j = 0; j < i; j++) {
      if (!vector_dot_product(n, b_norm[j], b_norm[j], &d))
        return false;
      if (d == 0.0)
        return false;
      if (!vector_dot_product(n, b_norm[i], b_norm[j], &t))
        return false;
      u[matrix_index(n, n, i, j)] = t / d;
      vector_zero(n, &temp);
      if (!vector_scalar_mult(n, (t / d),  b_norm[j], &temp))
        return false;
      if (!vector_sub(n, b_norm[i],  temp, &b_norm[i]))
        return false;
    }
  }
  return true;
}

// args are input and output
bool size_reduce(int n, real_vector* b, real_vector* b_norm, double* u) {
  return true;
}

bool lll(int n, real_vector* b) {
  return true;
}
