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
// 
// File: schooftest.cc

#include "cryptotypes.h"
#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "util.h"
#include "ecc.h"
#include "indeterminate.h"
#include "ecc_symbolic.h"
#include "keys.h"

uint64_t  cycles_per_second= 10;


class SchoofTest : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void SchoofTest::SetUp() {
}

void SchoofTest::TearDown() {
}

Polynomial* one_poly= NULL;
Polynomial* x_poly= NULL;
Polynomial* x_plus_one_poly= NULL;

bool InitPolys(BigNum* c) {
  // p(x)= 1
  one_poly= new Polynomial(1, 1, *c);
  one_poly->c_[0]->value_[0]= 1ULL;
  // p(x)= x
  x_poly= new Polynomial(1, 2, *c);
  x_poly->c_[1]->value_[0]= 1ULL;
  // p(x)= x+1
  x_plus_one_poly= new Polynomial(1, 2, *c);
  x_plus_one_poly->c_[0]->value_[0]= 1ULL;
  x_plus_one_poly->c_[1]->value_[0]= 1ULL;
  return true;
}

bool SimpleSymbolicTest() {
  BigNum      m(5);
  BigNum      n(5);
  BigNum      r(5);
  extern      bool SquareRoot(BigNum&, BigNum&);
  int         k= 7;
  int         j;
  uint64_t    primes[7]= {2ULL, 5ULL, 11ULL, 13ULL, 17ULL, 19ULL, 23ULL};
  uint64_t    sols[7]= {1ULL,0ULL,1ULL,1ULL,0ULL,0ULL,1ULL};
  BigNum      composite_modulus(8);
  BigNum      composite_solution(8);
  extern      bool ComputeCompositeSolutionUsingCrt(int, uint64_t*, uint64_t*,
                              BigNum&, BigNum&);
  extern      bool PickPrimes(int*, uint64_t*, BigNum&);
  int         num_primes= 0;
  uint64_t    prime_list[100];
  BigNum      p(12);

  m.value_[0]= 1ULL;
  m.Normalize();
  if(!BigShift(m, 39, n))
    return false;
  if(!SquareRoot(n, r))
    return false;
  m.ZeroNum();
  if(!BigUnsignedMult(r, r, m))
    return false;
  printf("The square root of ");
  PrintNumToConsole(n, 10ULL);
  printf(" is ");
  PrintNumToConsole(r, 10ULL);
  printf(", squared again is ");
  PrintNumToConsole(m, 10ULL);
  printf("\n");
  for(j=0; j<k; j++) {
    printf("x= %lld (mod %lld)\n", sols[j], primes[j]);
  }
  if(!ComputeCompositeSolutionUsingCrt(k, primes, sols, composite_modulus, composite_solution))
    return false;
  printf("composite modulus is ");
  PrintNumToConsole(composite_modulus, 10ULL);
  printf(", composite solution is ");
  PrintNumToConsole(composite_solution, 10ULL);
  printf("\n");

  BigShift(Big_One, 80, p);
  if(!PickPrimes(&num_primes, prime_list, p)) {
    printf("PickPrimes failed\n");
    return false;
  }
  printf("\nbound: "); PrintNumToConsole(p, 10ULL); printf("\n");
  printf("num_primes: %d\n", num_primes);
  for(j=0; j<num_primes; j++) {
    printf("%lld, ", prime_list[j]);
    if((j%20)==19)
      printf("\n");
  }
  printf("\n");

  printf("\n");
  if(!InitEccCurves()) {
    printf("InitEccCurves failed\n");
    return false;
  }
  extern EccKey   P256_Key;
  Polynomial curve_poly(8, 5, *P256_Key.c_.p_);
  if(!PolyFromCurve(P256_Key.c_, curve_poly)) {
    printf("PolyFromCurve failed\n");
    return false;
  }
  printf("curve prime: "); PrintNumToConsole(*P256_Key.c_.p_, 10ULL); printf("\n");
  curve_poly.Print();
  RationalPoly  r1_x(8, 4, *P256_Key.c_.p_);
  RationalPoly  r1_y (8, 4, *P256_Key.c_.p_);
  if(!MakeSymbolicIdentity(r1_x, r1_y)) {
    printf("MakeSymbolicIdentity failed\n");
    return false;
  }
  printf("\nNeutral element: ");
  r1_x.Print(); 
  printf(",\n");
  r1_y.Print(); 
  printf("\n");
  if(!IsSymbolicIdentity(r1_x, r1_y)) {
    printf("IsSymbolicIdentity failed\n");
    return false;
  }
  printf("IsSymbolicIdentity succeeded\n");

  RationalPoly  r2_x(8, 4, *P256_Key.c_.p_);
  RationalPoly  r2_y(8, 4, *P256_Key.c_.p_);
  RationalPoly  r3_x(8, 4, *P256_Key.c_.p_);
  RationalPoly  r3_y(8, 4, *P256_Key.c_.p_);

  OneRational(r2_y);
  ZeroRational(r2_x);
  r2_x.top_->c_[1]->value_[0]= 1ULL;
  r2_x.top_->c_[1]->Normalize();
  if(!EccSymbolicAdd(curve_poly, r1_x, r1_y, r2_x, r2_y, r3_x, r3_y)) {
    printf("EccSymbolicAdd 1 failed\n");
    return false;
  }
  printf("["); r1_x.Print();
  printf(", "); r1_y.Print();
  printf("] + ["); r2_x.Print();
  printf(", "); r2_y.Print();
  printf("] = ["); r3_x.Print();
  printf(", "); r3_y.Print(); printf("]\n");
  

  // EccSymbolicAdd(Polynomial& curve_poly, RationalPoly& in1_x, RationalPoly& in1_y,
  //                RationalPoly& in2_x, RationalPoly& in2_y,
  //                RationalPoly& out_x, RationalPoly& out_y)
  // EccSymbolicSub(Polynomial& curve_poly,
  //                   RationalPoly& in1_x, RationalPoly& in1_y,
  //                   RationalPoly& in2_x, RationalPoly& in2_y,
  //                   RationalPoly& out_x, RationalPoly& out_y)
  // EccSymbolicMult(Polynomial& curve_poly, BigNum& m,
  //                    RationalPoly& in_x, RationalPoly& in_y,
  //                    RationalPoly& out_x, RationalPoly& out_y)
  // ReducedEccSymbolicMult(Polynomial& curve_poly,
  //                    Polynomial& mod_poly, BigNum& m,
  //                    RationalPoly& in_x, RationalPoly& in_y,
  //                    RationalPoly& out_x, RationalPoly& out_y)
  // ReducedRaisetoLargePower(RationalPoly& inx, RationalPoly& iny, BigNum& e,
  //                      Polynomial& curve_poly, Polynomial& mod_poly,
  //                      RationalPoly& outx, RationalPoly& outy)
  // EccSymbolicMultEndomorphism(Polynomial& curve_poly, BigNum& m,
  //                                RationalPoly& out_x, RationalPoly& out_y)
  // EccSymbolicPowerEndomorphism(Polynomial& curve_poly, BigNum& e,
  //                                RationalPoly& out_x, RationalPoly& out_y)
  // RationalPolyNegate(RationalPoly& a)
  return true;
}

bool SimpleSchoofTest() {
  // InitPhi(int n)
  // Compute_t_mod_2(Polynomial& curve_poly, uint64_t* result)
  // Compute_t_mod_l(Polynomial& curve_poly, uint64_t l, uint64_t* result)
  // schoof(EccCurve& curve, BigNum& order)

  return true;
}
 
TEST(SimpleTest, SimpleTest) {
  EXPECT_TRUE(SimpleSymbolicTest());
  EXPECT_TRUE(SimpleSchoofTest());
}

DEFINE_string(log_file, "schooftest.log", "schooftest file name");

int main(int an, char** av) {

  BigNum  c(1,31ULL);

  if(!InitPolys(&c)) {
    printf("Can't init polys\n");
    return 1;
  }
  ::testing::InitGoogleTest(&an, av);
  if(!InitUtilities(FLAGS_log_file.c_str())) {
    printf("InitUtilities() failed\n");
    return 1;
  }
  cycles_per_second= CalibrateRdtsc();
  printf("Cycles per second on this machine: %lld\n\n", cycles_per_second);
  int result= RUN_ALL_TESTS();
  CloseUtilities();
  return result;
}


