// Copyright 2014-2020, John Manferdelli, All Rights Reserved.
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
// File: test_arm_big_num.cc

#include <crypto_support.h>
#include <arm64_digit_arith.h>
#include <big_num.h>
#include <big_num_functions.h>

void print_compare_val(int k) {
  switch(k) {
  case 1:
    printf(" > ");
    break;
  case 0:
    printf(" = ");
    break;
  case -1:
    printf(" < ");
    break;
  }
}

int main(int an, char** av) {

#if 0
  extern void instruction_test(uint64_t a, uint64_t b, uint64_t* c, uint64_t* d);
  uint64_t a, b, c, d;

  a = 10;
  b = 0;
  c = 0;
  d = 0;

  instruction_test(a, b, &c, &d);
  printf("%lu --> %lu\n", a, d);
#else
  uint64_t a, b, carry_in, carry, result;
  carry_in = 1;
  carry = carry_in;
  result = 0;
  a = 0xffffffffffffffffULL;
  b = 2;
  u64_add_step(a, b, &result, &carry);
  printf("\nu64_add_step: ");
  printf("%lx + %lx  + %lx = %lx, carry_out: %lx\n", a, b, carry_in, result, carry);

  uint64_t r1, r2;
  a = 0xffffffffffffffffULL;
  b = 0x100;
  r1 = 0;
  r2 = 0;
  printf("\nu64_mult_step: ");
  u64_mult_step(a, b, &r1, &r2);
  printf("%lx *  %lx =  %016lx %016lx\n", a, b, r1, r2);

  // Compare tests

  big_num A(10, 0xfffffffffffffff8ULL);
  big_num B(10, 0x100ULL);
  big_num C(10);
  C.zero_num();

  printf("\nbig_compare\n");
  int k = big_compare(A, B);
  A.print();
  print_compare_val(k);
  B.print();
  printf("\n");
  k = big_compare(A, A);
  A.print();
  print_compare_val(k);
  A.print();
  printf("\n");
  k = big_compare(B, A);
  B.print();
  print_compare_val(k);
  A.print();
  printf("\n");
  

  printf("\nbig_num add\n");
  A.print();
  printf(" + ");
  B.print();
  printf(" = ");
  if (big_add(A, B, C)) {
    C.print();
    printf("\n");
  } else {
    printf(" --- ADD failed\n");
  }

  printf("\nbig_num sub\n");
  A.print();
  printf(" - ");
  B.print();
  printf(" = ");
  if (big_sub(A, B, C)) {
    C.print();
    printf("\n");
  } else {
    printf(" --- sub failed\n");
  }

  printf("\nbig_num mult\n");
  A.print();
  printf(" * ");
  B.print();
  printf(" = ");
  if (big_mult(A, B, C)) {
    C.print();
    printf("\n");
  } else {
    printf(" --- Mult failed\n");
  }

#if 1
  printf("\nbig_num div\n");
  big_num A1(10, 0xfffffffffffffff8ULL);
  uint64_t* a1p = A1.value_ptr();
  a1p[1]=  0xffff;
  A1.normalize();
  big_num B1(10, 0x100ULL);
  big_num Q(10);
  big_num R(10);

  A1.print();
  printf(" / ");
  B1.print();
  printf(" = ");
  if (big_unsigned_euclid(A1, B1, Q, R)) {
    Q.print();
    printf(" rem ");
    R.print();
    printf("\n");
  } else {
    printf(" --- Div failed\n");
  }
#endif

  A.zero_num();
  uint64_t* ap = A.value_ptr();
  ap[0] = 0xffff000011110000ULL;
  ap[1] = 0xcccc000055550000ULL;
  ap[2] = 0x0000bbbb00006666ULL;
  A.normalize();

  printf("\nbig_num shift\n");
  if (big_shift(A, 2, C)) {
    A.print();
    printf(" << 2w = ");
    C.print();
    printf("\n");
  } else {
    printf("big_shift error\n");
  }
  if (big_shift(A, -2, C)) {
    A.print();
    printf(" >> 2w = ");
    C.print();
    printf("\n");
  } else {
    printf("big_shift error\n");
  }
  if (big_shift(A, 6, C)) {
    A.print();
    printf(" << 6b = ");
    C.print();
    printf("\n");
  } else {
    printf("big_shift error\n");
  }
  if (big_shift(A, -6, C)) {
    A.print();
    printf(" >> 6b = ");
    C.print();
    printf("\n");
  } else {
    printf("big_shift error\n");
  }
  if (big_shift(A, 67, C)) {
    A.print();
    printf(" << 67b = ");
    C.print();
    printf("\n");
  } else {
    printf("big_shift error\n");
  }
  if (big_shift(A, -67, C)) {
    A.print();
    printf(" >> 67b = ");
    C.print();
    printf("\n");
  } else {
    printf("big_shift error\n");
  }

  big_num a1(5, 46ULL);
  big_num b1(5, 7ULL);
  big_num e(5, 40ULL);
  big_num m(5, 41ULL);
  big_num q(5);
  big_num r(5);
  big_num x(5);
  big_num y(5);
  big_num g(5);

  printf("\nMod tests:\n");
  if (big_mod(a1, m, r))  {
    a1.print();
    printf(" big_mod ");
    m.print();
    printf(" is ");
    r.print();
    printf("\n");
  } else {
    printf("big_mod error\n");
  } 

  r.zero_num();
  if (big_mod_add(a1, b1, m, r)) {
    a1.print();
    printf(" + ");
    b1.print();
    printf(" (mod ");
    m.print();
    printf(") is ");
    r.print();
    printf("\n");
  } else {
    printf("big_mod_add error\n");
  } 

  r.zero_num();
  if (big_mod_sub(a1, b1, m, r)) {
    a1.print();
    printf(" - ");
    b1.print();
    printf(" (mod ");
    m.print();
    printf(") is ");
    r.print();
    printf("\n");
  } else {
    printf("big_mod_sub error\n");
  } 

  r.zero_num();
  if (big_square(a1, r)) {
    a1.print();
    printf(" * ");
    a1.print();
    printf(" = ");
    r.print();
    printf("\n");
  } else {
    printf("big_square error\n");
  } 

  r.zero_num();
  if (big_mod(a1, m, r)) {
    a1.print();
    printf(" (mod  ");
    m.print();
    printf(") = ");
    r.print();
    printf("\n");
  } else {
    printf("big_mod error\n");
  } 

  r.zero_num();
  if (big_mod_neg(a1, m, r)) {
    printf(" - ");
    a1.print();
    printf(" = ");
    r.print();
    printf("\n");
  } else {
    printf("big_modNeg error\n");
  } 

  r.zero_num();
  if (big_mod_mult(a1, b1, m, r)) {
    a1.print();
    printf(" * ");
    b1.print();
    printf(" mod( ");
    m.print();
    printf(") = ");
    r.print();
    printf("\n");
  } else {
    printf("big_mod_mult error\n");
  } 

  r.zero_num();
  if (big_mod_square(a1, m, r)) {
    a1.print();
    printf(" * ");
    a1.print();
    printf(" mod( ");
    m.print();
    printf(") = ");
    r.print();
    printf("\n");
  } else {
    printf("big_mod_square error\n");
  } 

  q.zero_num();
  r.zero_num();
  if (big_unsigned_euclid(a1, b1, q, r)) {
    a1.print();
    printf(" = ");
    b1.print();
    printf(" * ");
    q.print();
    printf(" + ");
    r.print();
    printf("\n");
  } else {
    printf("big_unsigned_euclid error\n");
  }

  g.zero_num();
  x.zero_num();
  y.zero_num();
  if (big_extended_gcd(a1, b1, x, y, g)) {
    a1.print();
    printf(" * ");
    x.print();
    printf(" + ");
    b1.print();
    printf(" * ");
    y.print();
    printf(" = ");
    g.print();
    printf("\n");
  } else {
    printf("big_extended_gcd error\n");
  } 

  r.zero_num();
  if (big_mod_inv(a1, m, r)) {
    printf("(");
    a1.print();
    printf(")**-1 (mod ");
    m.print();
    printf(") = ");
    r.print();
    printf("\n");
  } else {
    printf("big_modInv error\n");
  } 

  r.zero_num();
  if (big_mod_div(a1, b1, m, r)) {
    a1.print();
    printf(" / ");
    b1.print();
    printf(" (mod ");
    m.print();
    printf(") = ");
    r.print();
    printf("\n");
  } else {
    printf("big_mod_div error\n");
  } 

  r.zero_num();
  if (big_mod_exp(b1, e, m, r)) {
    b1.print();
    printf(" ** ");
    e.print();
    printf(" (mod ");
    m.print();
    printf(") = ");
    r.print();
    printf("\n");
  } else {
    printf("big_mod_exp error\n");
  } 

  big_num m1(5, 37ULL);
  big_num m2(5, 41ULL);
  big_num s1(5, 7ULL);
  big_num s2(5, 1ULL);
  r.zero_num();
  if(big_crt(s1, s2, m1, m2, r)) {
    s1.print();
    printf(" (mod ");
    m1.print();
    printf("),  ");
    s2.print();
    printf(" (mod ");
    m2.print();
    printf("), common soln is ");
    r.print();
    printf("\n");
  } else {
    printf("big_crt error\n");
  } 

  // Divide by digit test
  m1.zero_num();
  uint64_t* pm = m1.value_ptr();
  uint64_t d = 0ULL;
  b = 10ULL;
  pm[0] = 4;
  pm[1] = 6000;
  pm[2] = 200;
  pm[3] = 2929;
  m1.normalize();

  printf("\ndigit_array_short_division_algorithm test\n");
  m2.zero_num();
  int size_out = m2.size();
  if (!digit_array_short_division_algorithm(m1.size(), m1.value_ptr(), b, &size_out, m2.value_ptr(), &d)) {
    m1.print();
    printf(" / %ld remainder %ld, quotient is ", b, d);
    m2.normalize();
    m2.print();
    printf("\n");
  } else {
    printf("digit_array_short_division_algorithm error\n");
  }

#endif

  printf("done\n");
  return 0;
}

