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
// Project: New Cloudproxy Crypto
// File: indeterminatetest.cc

#include "cryptotypes.h"
#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "util.h"
#include "indeterminate.h"

uint64_t cycles_per_second = 10;

class IndeterminateTest : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void IndeterminateTest::SetUp() {}

void IndeterminateTest::TearDown() {}

Polynomial* one_poly = nullptr;
Polynomial* x_poly = nullptr;
Polynomial* x_plus_one_poly = nullptr;

bool InitPolys(BigNum* c) {
  // p(x)= 1
  one_poly = new Polynomial(1, 1, *c);
  one_poly->c_[0]->value_[0] = 1ULL;
  // p(x)= x
  x_poly = new Polynomial(1, 2, *c);
  x_poly->c_[1]->value_[0] = 1ULL;
  // p(x)= x+1
  x_plus_one_poly = new Polynomial(1, 2, *c);
  x_plus_one_poly->c_[0]->value_[0] = 1ULL;
  x_plus_one_poly->c_[1]->value_[0] = 1ULL;
  return true;
}

bool SimplePolyTest() {
  one_poly->Print(true);
  printf("\n");
  x_plus_one_poly->Print(true);
  printf("\n");
  Polynomial sum(1, 3, *one_poly->m_);
  Polynomial diff(1, 3, *one_poly->m_);
  Polynomial prod(1, 4, *one_poly->m_);
  Polynomial prod2(1, 5, *one_poly->m_);
  Polynomial q(1, 5, *one_poly->m_);
  Polynomial r(1, 5, *one_poly->m_);

  printf("Degree(x+1): %d\n", x_plus_one_poly->Degree());

  if (!PolyAdd(*one_poly, *x_poly, sum)) {
    printf("PolyAdd fails\n");
    return false;
  }
  printf("x+1: ");
  sum.Print(true);
  printf("\n");
  if (!PolySub(*x_poly, *x_poly, diff)) {
    printf("PolySub fails\n");
    return false;
  }
  printf("x-x: ");
  diff.Print(true);
  printf("\n");
  if (!PolyMult(*x_poly, *x_plus_one_poly, prod)) {
    printf("PolyMult fails\n");
    return false;
  }
  printf("x(x+1): ");
  prod.Print(true);
  printf("\n");
  if (!MultiplyPolyByMonomial(*x_plus_one_poly, 1, Big_Two, prod2)) {
    printf("MultiplyPolyByMonomial fails\n");
    return false;
  }
  printf("x(x+1): ");
  prod2.Print(true);
  printf("\n");

  if (!PolyEuclid(*x_plus_one_poly, *x_poly, q, r)) {
    printf("PolyEuclid fails\n");
    return false;
  }
  x_plus_one_poly->Print(true);
  printf(" = ");
  x_poly->Print(true);
  printf(" * ");
  q.Print(true);
  printf(" + ");
  r.Print(true);
  printf("\n");

  ZeroPoly(q);
  ZeroPoly(r);
  if (!PolyEuclid(*x_poly, *x_plus_one_poly, q, r)) {
    printf("PolyEuclid fails\n");
    return false;
  }
  x_poly->Print(true);
  printf(" = ");
  x_plus_one_poly->Print(true);
  printf(" * ");
  q.Print(true);
  printf(" + ");
  r.Print(true);
  printf("\n");

  Polynomial x(1, 5, *one_poly->m_);
  Polynomial y(1, 5, *one_poly->m_);
  Polynomial g(1, 5, *one_poly->m_);
  if (!PolyExtendedGcd(*x_poly, *x_plus_one_poly, x, y, g)) {
    printf("PolyExtendedGcd fails\n");
    return false;
  }
  x_poly->Print(true);
  printf(" * ");
  x.Print(true);
  printf(" + ");
  x_plus_one_poly->Print(true);
  printf(" * ");
  y.Print(true);
  printf(" = ");
  g.Print(true);
  printf("\n");
  return true;
}

bool SimpleRationalTest() {
  RationalPoly one_rational(1, 3, *one_poly->m_, *x_plus_one_poly,
                            *x_plus_one_poly);
  RationalPoly x_rational(1, 3, *one_poly->m_, *x_poly, *one_poly);
  RationalPoly x_over_x_plus_one_rational(1, 3, *one_poly->m_, *x_poly,
                                          *x_plus_one_poly);
  one_rational.Print(true);
  printf("\n");
  one_rational.Reduce();
  one_rational.Print(true);
  printf("\n");
  printf("x: ");
  x_rational.Print(true);
  printf("\n");
  printf("x/x+1: ");
  x_over_x_plus_one_rational.Print(true);
  printf("\n");
  RationalPoly sum(1, 3, *one_poly->m_);
  RationalPoly diff(1, 3, *one_poly->m_);
  RationalPoly prod(1, 4, *one_poly->m_);
  RationalPoly div(1, 5, *one_poly->m_);

  if (!RationalAdd(x_rational, x_over_x_plus_one_rational, sum)) {
    printf("RationalAdd fails\n");
    return false;
  }
  printf("x+x/x+1: ");
  sum.Print(true);
  printf("\n");
  if (!RationalSub(x_rational, x_over_x_plus_one_rational, diff)) {
    printf("RationalSub fails\n");
    return false;
  }
  printf("x-x/x+1: ");
  diff.Print(true);
  printf("\n");
  if (!RationalMult(x_rational, x_over_x_plus_one_rational, prod)) {
    printf("RationalMult fails\n");
    return false;
  }
  printf("x*x/(x+1): ");
  prod.Print(true);
  printf("\n");
  if (!RationalDiv(x_rational, x_over_x_plus_one_rational, div)) {
    printf("RationalMult fails\n");
    return false;
  }
  printf("x/x/(x+1): ");
  div.Print(true);
  printf("\n");
  return true;
}

TEST(SimpleTest, SimpleTest) {
  EXPECT_TRUE(SimplePolyTest());
  EXPECT_TRUE(SimpleRationalTest());
}

DEFINE_string(log_file, "indeterminatetest.log", "indeterminatetest file name");

int main(int an, char** av) {
  BigNum c(1, 31ULL);

  if (!InitPolys(&c)) {
    printf("Can't init polys\n");
    return 1;
  }
  ::testing::InitGoogleTest(&an, av);
  if (!InitUtilities(FLAGS_log_file.c_str())) {
    printf("InitUtilities() failed\n");
    return 1;
  }
  cycles_per_second = CalibrateRdtsc();
  printf("Cycles per second on this machine: %lld\n\n", cycles_per_second);
  int result = RUN_ALL_TESTS();
  CloseUtilities();
  return result;
}
