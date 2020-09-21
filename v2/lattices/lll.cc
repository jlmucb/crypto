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
// File: lll.cc

#include "crypto_support.h"
#include "lattice.h"


void print_matrix(int n, int m, double* u) {
  for(int i = 0; i < n; i++) {
    for (int j = 0; j < m; j++)
      printf("%lf  ", u[matrix_index(n, m, i, j)]);
    printf("\n");
  }
}

void print_vector(real_vector& v) {
  real_vector::iterator it;

  it = v.begin();
  printf("(");
  while(1) {
    printf(" %.4lf", *it);
    it++;
    if (it == v.end()) 
      break;
    printf(", ");
  }
  printf(" )");
}


bool vector_alloc(int n, real_vector* v) {
  v->clear();
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
    u[matrix_index(n, n, i, i)] = 1.0;
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
      if (!vector_sub(n, b_norm[i], temp, &b_norm[i]))
        return false;
    }
  }
  return true;
}

const int RUNAWAY = 1000000;

int64_t closest_int(double x) {
  uint64_t a = (uint64_t) x;
  if (fabs(x - (double)a) <= 0.5)
      return a;
  return a + 1ULL;
}

// args are input and output
bool size_reduce(int n, real_vector* b, real_vector* b_norm, double* u) {
  real_vector v_t;
  double t;
  int64_t i_u;

  if (!vector_alloc(n, &v_t))
      return false;

  if (!gso(n, b, b_norm, u)) 
      return false;

  for (int i = 1; i < n; i++) {
    for (int j = (i - 1); j >= 0; j--) {
      vector_zero(n, &v_t);
      i_u = closest_int(u[matrix_index(n, n, i, j)]);
      if (!vector_scalar_mult(n, (const double) i_u,  b[j], &v_t))
        return false;
      if (!vector_sub(n, b[i], b[j], &b[i]))
        return false;
      for (int k = 0; k <= j; k++) {
        u[matrix_index(n, n, i, k)] -= ((double) i_u) * u[matrix_index(n, n, j, k)];
      }
    }
  }

  return true;
}

bool lovacz_condition(double delta, const double c,
                      const double B1, const double B2) {
printf("LC %lf  %lf %lf (%lf, %lf)\n", c, B1, B2, (delta - c*c) * B1, B2);
  if (((delta - c*c) * B1) <= B2)
    return true;
  else
    return false;
}

bool vector_swap(int n, real_vector* b1, real_vector* b2) {
  double t;

printf("swap ");
print_vector(*b1);print_vector(*b2);
printf("\n");

  for (int i = 0; i < n; i++) {
    t = (*b1)[i];
    (*b1)[i] = (*b2)[i];
    (*b2)[i] = t;
  }
  return true;
}

bool lll(const double delta, int n, real_vector* b) {
  double* B = new double[n];
  if (B == nullptr)
    return false;
  real_vector* b_norm = new real_vector[n];
  if (b_norm == nullptr)
    return false;
  double* u = new double[n * n];
  if (u == nullptr)
    return false;
  bool ret = false;
  matrix_zero(n, n, u);
  for (int i = 0; i < n; i++) {
    vector_alloc(n, b_norm);
    B[i] = 0.0;
  }

  bool restart;
  for (int i = 0; i < RUNAWAY; i++) {
    if (!gso(n, b, b_norm, u)) {
      goto done;
    }
printf("before size reduce u: \n");
print_matrix(n, n, u);
   if (!size_reduce(n, b, b_norm, u)) {
      goto done;
    }
printf("after size reduce u: \n");
print_matrix(n, n, u);
    for (int j = 0; j < n; j++) {
      if(!vector_dot_product(n, b_norm[j], b_norm[j], &B[j])) {
        goto done;
      }
    }
    // check Lovacz condition
    for (int j = 0; j < (n - 1); j++) {
      if (!lovacz_condition(delta, u[matrix_index(n, n, j + 1, j)],
                            B[j], B[j+1])) {
        vector_swap(n, &b[j], &b[j + 1]);
        restart = true;
        break;
      } else {
      }
      restart = false;
    }
    if (restart)
      continue;
    ret = true;
    break;
  }

done:
  if (B != nullptr)
    delete []B;
  if (b_norm != nullptr)
    delete []b_norm;
  if (u != nullptr)
    delete []u;
  return ret;
}
