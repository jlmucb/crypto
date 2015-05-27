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

uint64_t cycles_per_second = 10;

class SchoofTest : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void SchoofTest::SetUp() {}

void SchoofTest::TearDown() {}

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

bool BsgsTest() {
  printf("BsgsTest()\n");

  /*
   * Example
   *  E: y^2= x^3-10x+21 (mod 557)
   *  P= (2,3)
   *  Q= 558P= (418, 33)
   *  m=5>(557)^(1/4)
   *  jP= O, (2,3), (58, 164), (44, 294), (56, 339), (132, 364)
   *  k=1, Q= kP+(2m)P= (2,3)
   *  (q+1+2m-j)P= 567P= O
   *  567= 3^4 x 7
   *  (567/3)P= 189P= O
   *  |P|=189
   */
  BigNum test_a(2, 547ULL);
  BigNum test_b(2, 21ULL);
  BigNum test_p(2, 557ULL);
  BigNum test_P_x(2, 2ULL);
  BigNum test_P_y(2, 3ULL);
  BigNum test_order(2);
  CurvePoint test_P(test_P_x, test_P_y);
  EccCurve test_curve(test_a, test_b, test_p);
  extern bool eccbsgspointorder(EccCurve&, CurvePoint&, BigNum&);

  printf("Curve: ");
  test_curve.PrintCurve();
  printf("P: ");
  test_P.PrintPoint();
  printf("\n");
  if (!eccbsgspointorder(test_curve, test_P, test_order)) {
    printf("eccbsgspointorder failed\n");
    return false;
  }
  printf("order: ");
  PrintNumToConsole(test_order, 10ULL);
  printf("\n");
  return true;
}

bool SimpleSymbolicTest() {
  printf("SimpleSymbolicTest()\n");
  BigNum m(5);
  BigNum n(5);
  BigNum r(5);
  extern bool SquareRoot(BigNum&, BigNum&);
  int k = 7;
  int j;
  uint64_t primes[7] = {2ULL, 5ULL, 11ULL, 13ULL, 17ULL, 19ULL, 23ULL};
  uint64_t sols[7] = {1ULL, 0ULL, 1ULL, 1ULL, 0ULL, 0ULL, 1ULL};
  BigNum composite_modulus(8);
  BigNum composite_solution(8);
  extern bool ComputeCompositeSolutionUsingCrt(int, uint64_t*, uint64_t*,
                                               BigNum&, BigNum&);
  extern bool PickPrimes(int*, uint64_t*, BigNum&);
  int num_primes = 0;
  uint64_t prime_list[100];
  BigNum p(12);

  m.value_[0] = 1ULL;
  m.Normalize();
  if (!BigShift(m, 39, n)) return false;
  if (!SquareRoot(n, r)) return false;
  m.ZeroNum();
  if (!BigUnsignedMult(r, r, m)) return false;
  printf("The square root of ");
  PrintNumToConsole(n, 10ULL);
  printf(" is ");
  PrintNumToConsole(r, 10ULL);
  printf(", squared again is ");
  PrintNumToConsole(m, 10ULL);
  printf("\n");
  for (j = 0; j < k; j++) {
    printf("x= %lld (mod %lld)\n", sols[j], primes[j]);
  }
  if (!ComputeCompositeSolutionUsingCrt(k, primes, sols, composite_modulus,
                                        composite_solution))
    return false;
  printf("composite modulus is ");
  PrintNumToConsole(composite_modulus, 10ULL);
  printf(", composite solution is ");
  PrintNumToConsole(composite_solution, 10ULL);
  printf("\n");

  BigShift(Big_One, 80, p);
  if (!PickPrimes(&num_primes, prime_list, p)) {
    printf("PickPrimes failed\n");
    return false;
  }
  printf("\nbound: ");
  PrintNumToConsole(p, 10ULL);
  printf("\n");
  printf("num_primes: %d\n", num_primes);
  for (j = 0; j < num_primes; j++) {
    printf("%lld, ", prime_list[j]);
    if ((j % 20) == 19) printf("\n");
  }
  printf("\n");

  printf("\n");
  if (!InitEccCurves()) {
    printf("InitEccCurves failed\n");
    return false;
  }
  extern EccKey P256_Key;
  Polynomial curve_poly(8, 5, *P256_Key.c_.p_);
  if (!PolyFromCurve(P256_Key.c_, curve_poly)) {
    printf("PolyFromCurve failed\n");
    return false;
  }
  printf("curve prime: ");
  PrintNumToConsole(*P256_Key.c_.p_, 10ULL);
  printf("\n");
  curve_poly.Print();
  RationalPoly r1_x(8, 4, *P256_Key.c_.p_);
  RationalPoly r1_y(8, 4, *P256_Key.c_.p_);
  if (!MakeSymbolicIdentity(r1_x, r1_y)) {
    printf("MakeSymbolicIdentity failed\n");
    return false;
  }
  printf("\nNeutral element: ");
  r1_x.Print();
  printf(",\n");
  r1_y.Print();
  printf("\n");
  if (!IsSymbolicIdentity(r1_x, r1_y)) {
    printf("IsSymbolicIdentity failed\n");
    return false;
  }
  printf("IsSymbolicIdentity succeeded\n");

  // EccSymbolicSub(Polynomial& curve_poly, RationalPoly& in1_x, RationalPoly&
  // in1_y,
  //    RationalPoly& in2_x, RationalPoly& in2_y, RationalPoly& out_x,
  //    RationalPoly& out_y)

  RationalPoly r2_x(8, 20, *P256_Key.c_.p_);
  RationalPoly r2_y(8, 20, *P256_Key.c_.p_);
  RationalPoly r3_x(8, 20, *P256_Key.c_.p_);
  RationalPoly r3_y(8, 20, *P256_Key.c_.p_);

  OneRational(r2_y);
  ZeroRational(r2_x);
  r2_x.top_->c_[1]->value_[0] = 1ULL;
  r2_x.top_->c_[1]->Normalize();
  if (!EccSymbolicAdd(curve_poly, r1_x, r1_y, r2_x, r2_y, r3_x, r3_y)) {
    printf("EccSymbolicAdd 1 failed\n");
    return false;
  }
  printf("[");
  r1_x.Print();
  printf(", ");
  r1_y.Print();
  printf("] + [");
  r2_x.Print();
  printf(", ");
  r2_y.Print();
  printf("] = [");
  r3_x.Print();
  printf(", ");
  r3_y.Print();
  printf("]\n");

  printf("\n");
  ZeroRational(r3_x);
  ZeroRational(r3_y);
  if (!EccSymbolicAdd(curve_poly, r2_x, r2_y, r1_x, r1_y, r3_x, r3_y)) {
    printf("EccSymbolicAdd 2 failed\n");
    return false;
  }
  printf("[");
  r2_x.Print();
  printf(", ");
  r2_y.Print();
  printf("] + [");
  r1_x.Print();
  printf(", ");
  r1_y.Print();
  printf("] = [");
  r3_x.Print();
  printf(", ");
  r3_y.Print();
  printf("]\n");

  printf("\n");
  ZeroRational(r3_x);
  ZeroRational(r3_y);
  if (!EccSymbolicAdd(curve_poly, r2_x, r2_y, r2_x, r2_y, r3_x, r3_y)) {
    printf("EccSymbolicAdd 3 failed\n");
    return false;
  }
  printf("[");
  r2_x.Print();
  printf(", ");
  r2_y.Print();
  printf("] + [");
  r2_x.Print();
  printf(", ");
  r2_y.Print();
  printf("] = [");
  r3_x.Print();
  printf(", ");
  r3_y.Print();
  printf("]\n");

  printf("\n");
  ZeroRational(r3_x);
  ZeroRational(r3_y);
  if (!EccSymbolicSub(curve_poly, r2_x, r2_y, r2_x, r2_y, r3_x, r3_y)) {
    printf("EccSymbolicSub 1 failed\n");
    return false;
  }
  printf("[");
  r2_x.Print();
  printf(", ");
  r2_y.Print();
  printf("] - [");
  r2_x.Print();
  printf(", ");
  r2_y.Print();
  printf("] = [");
  r3_x.Print();
  printf(", ");
  r3_y.Print();
  printf("]\n");

  // x^19= x^2+13x+14 (mod x^3 +2x +1)
  // (x^19-x, x^3+2x+1)=1
  BigNum small_p(2, 19ULL);
  small_p.Normalize();
  Polynomial p1(8, 8, small_p);
  Polynomial p2(8, 8, small_p);
  Polynomial p3(8, 8, small_p);
  Polynomial mod_poly(8, 5, small_p);

  ZeroPoly(curve_poly);
  // mod_poly= x^3+2x+1 (mod 19)
  curve_poly.c_[0]->value_[0] = 1ULL;
  curve_poly.c_[1]->value_[0] = 2ULL;
  curve_poly.c_[3]->value_[0] = 1ULL;
  curve_poly.c_[0]->Normalize();
  curve_poly.c_[1]->Normalize();
  curve_poly.c_[3]->Normalize();
  curve_poly.m_->CopyFrom(small_p);
  // p1= x
  p1.c_[1]->value_[0] = 1ULL;
  p1.c_[1]->Normalize();
  if (!ReducedRaisetoLargePower(p1, small_p, curve_poly, p2)) {
    printf("ReducedRaisetoLargePower failed\n");
    return false;
  }
  printf("[");
  p1.Print(true);
  printf("]^%d= ", (int)small_p.value_[0]);
  p2.Print(true);
  printf(" (mod  ");
  curve_poly.Print(true);
  printf(")\n");

  /*
   *  y^2= x^3+2x+1 (mod 19)
   *  #E(F_19)= 20-a
   *  phi_3= 3x^4+12x^2+12x-4
   *  phi_5= 5x^12+ 10x^10 + 7x^8 + 5x^7 + x^6 + 9x^5 + 12x^4 + 2x^3 + 5x^2 + 8x
   * + 8
   *  l=2, a=1 (2)
   *  l=3, a=2 (3)
   *    (x^361-x, phi_3)= x-8 !=1
   *  l=5, a=3 (5)
   *  a= -7.  So #E=27
   */

  RationalPoly in_x(8, 100, small_p);
  RationalPoly in_y(8, 100, small_p);
  RationalPoly out_x(8, 100, small_p);
  RationalPoly out_y(8, 100, small_p);
  extern Polynomial** Phi_array;
  ZeroRational(in_x);
  OneRational(in_y);
  ZeroRational(out_x);
  ZeroRational(out_y);
  in_x.top_->c_[1]->value_[0] = 1ULL;
  RationalPoly in2_x(8, 100, small_p);
  OneRational(in2_x);

  // m.value_[0]= 5ULL;
  m.value_[0] = 2ULL;
  m.Normalize();
  if (!EccSymbolicMult(curve_poly, m, in_x, in_y, out_x, out_y)) {
    printf("EccSymbolicMult fails\n");
    return false;
  }
  PrintNumToConsole(m, 10ULL);
  printf("[");
  in_x.Print(true);
  printf(", ");
  in_y.Print(true);
  printf("] = [");
  out_x.Print(true);
  printf(", ");
  out_y.Print(true);
  printf("]\n");

  if (!ReducedEccSymbolicMult(curve_poly, *Phi_array[3], m, in_x, in_y, out_x,
                              out_y)) {
    printf("ReducedEccSymbolicMult fails\n");
    return false;
  }
  PrintNumToConsole(m, 10ULL);
  printf("[");
  in_x.Print(true);
  printf(", ");
  in_y.Print(true);
  printf("] = [");
  out_x.Print(true);
  printf(", ");
  out_y.Print(true);
  printf("]\n");
  printf("mod_poly: ");
  Phi_array[3]->Print(true);
  printf("\n");

  if (!EccSymbolicMultEndomorphism(curve_poly, m, *Phi_array[3], out_x,
                                   out_y)) {
    printf("EccSymbolicMultEndomorphism fails\n");
    return false;
  }
  PrintNumToConsole(m, 10ULL);
  printf("[");
  in_x.Print(true);
  printf(", ");
  in_y.Print(true);
  printf("] = [");
  out_x.Print(true);
  printf(", ");
  out_y.Print(true);
  printf("]\n");
  printf("mod_poly: ");
  Phi_array[3]->Print(true);
  printf("\n");

  if (!EccSymbolicPowerEndomorphism(curve_poly, m, *Phi_array[3], out_x,
                                    out_y)) {
    printf("EccSymbolicPowerEndomorphism fails\n");
    return false;
  }
  PrintNumToConsole(m, 10ULL);
  printf("[");
  in_x.Print(true);
  printf(", ");
  in_y.Print(true);
  printf("] = [");
  out_x.Print(true);
  printf(", ");
  out_y.Print(true);
  printf("]\n");
  printf("mod_poly: ");
  Phi_array[3]->Print(true);
  printf("\n");

  if (!EccSymbolicAdd(curve_poly, in_x, in_y, in2_x, in_y, out_x, out_y)) {
    printf("EccSymbolicMult fails\n");
    return false;
  }
  printf("[");
  in_x.Print(true);
  printf(", ");
  in_y.Print(true);
  printf("  + [");
  printf("[");
  in2_x.Print(true);
  printf(", ");
  in_y.Print(true);
  printf("] = [");
  out_x.Print(true);
  printf(", ");
  out_y.Print(true);
  printf("]\n");
  return true;
}

bool SimplePhiTest() {
  printf("SimplePhiTest()\n");

  BigNum small_p(2, 19ULL);
  small_p.Normalize();
  Polynomial p1(8, 8, small_p);
  Polynomial p2(8, 8, small_p);
  Polynomial p3(8, 8, small_p);
  Polynomial curve_poly(8, 5, small_p);

  // curve_poly= x^3+2x+1 (mod 19)
  curve_poly.c_[0]->value_[0] = 1ULL;
  curve_poly.c_[1]->value_[0] = 2ULL;
  curve_poly.c_[3]->value_[0] = 1ULL;
  curve_poly.c_[0]->Normalize();
  curve_poly.c_[1]->Normalize();
  curve_poly.c_[3]->Normalize();
  curve_poly.m_->CopyFrom(small_p);
  printf("curve poly: ");
  curve_poly.Print(true);
  printf("\n");

  /*
   *  y^2= x^3+2x+1 (mod 19)
   *  #E(F_19)= 20-a
   *  phi_3= 3x^4+12x^2+12x-4
   *  phi_5= 5x^12+ 10x^10 + 7x^8 + 5x^7 + x^6 + 9x^5 + 12x^4 + 2x^3 + 5x^2 + 8x
   * + 8
   *  (x^19-x, x^3+2x+1)=1
   *  l=2, a=1 (2)
   *  l=3, a=2 (3)
   *    (x^361-x, phi_3)= x-8 !=1
   *  l=5, a=3 (5)
   *  a= -7.  So #E=27
   */
  extern Polynomial** Phi_array;
  extern bool PickPrimes(int*, uint64_t*, BigNum&);
  extern bool InitPhi(int, Polynomial&);
  extern bool Compute_t_mod_2(Polynomial&, uint64_t*);
  extern bool Compute_t_mod_l(Polynomial & curve_poly, uint64_t l,
                              uint64_t * result);
  extern bool ComputeCompositeSolutionUsingCrt(
      int n, uint64_t* moduli, uint64_t* solutions, BigNum& composite_modulus,
      BigNum& composite_solution);
  extern bool SquareRoot(BigNum&, BigNum&);
  int i;
  extern int Max_phi;
  int num_primes = 0;
  uint64_t primes[50];
  uint64_t solutions[50];
  BigNum order(4);
  BigNum s(4);
  BigNum t(4);
  BigNum composite_modulus(4);
  BigNum composite_solution(4);
  BigNum sqrt_p(4);
  BigNum hasse_bound(4);

  if (!SquareRoot(small_p, sqrt_p)) {
    printf("SquareRoot failed\n");
    return false;
  }
  if (!BigUnsignedMult(sqrt_p, Big_Two, hasse_bound)) {
    printf("BigUnsignedMultfailed\n");
    return false;
  }
  printf("hasse_bound: ");
  PrintNumToConsole(hasse_bound, 10ULL);
  printf("\n");

  if (!PickPrimes(&num_primes, primes, small_p)) {
    printf("PickPrimes failed\n");
    return false;
  }
  printf("selected primes\n");
  for (i = 0; i < num_primes; i++) {
    printf("%lld, ", primes[i]);
  }
  printf("\n");

  if (!InitPhi(primes[num_primes - 1], curve_poly)) {
    printf("InitPhi failed\n");
    return false;
  }
  for (i = 0; i <= Max_phi; i++) {
    printf("phi[%d], alloc %d: ", i, Phi_array[i]->num_c_);
    Phi_array[i]->Print(true);
    printf("\n");
  }

  bool ret = true;
  if (!Compute_t_mod_2(curve_poly, &solutions[0])) {
    printf("Compute_t_mod_2 failed\n");
    ret = false;
    goto done;
  }
  printf("Solution mod %lld is %lld\n", primes[0], solutions[0]);
  for (i = 1; i < num_primes; i++) {
    if (!Compute_t_mod_l(curve_poly, primes[i], &solutions[i])) {
      printf("Compute_t_mod_l failed\n");
      return false;
    }
  }
  for (i = 1; i < num_primes; i++) {
    printf("Solution mod %lld is %lld\n", primes[i], solutions[i]);
  }
  // compute t using CRT
  if (!ComputeCompositeSolutionUsingCrt(num_primes, primes, solutions,
                                        composite_modulus,
                                        composite_solution)) {
    ret = false;
    goto done;
  }
  printf("composite_modulus: ");
  PrintNumToConsole(composite_modulus, 10ULL);
  printf("\n");
  printf("composite_solution: ");
  PrintNumToConsole(composite_solution, 10ULL);
  printf("\n");
  // get #E = p+1-t
  order.ZeroNum();
  if (!BigUnsignedAdd(*curve_poly.m_, Big_One, s)) {
    ret = false;
    goto done;
  }
  if (BigCompare(composite_solution, hasse_bound) > 0) {
    if (!BigSub(composite_solution, composite_modulus, t)) {
      ret = false;
      goto done;
    }
  } else {
    t.CopyFrom(composite_solution);
  }
  printf("s: ");
  PrintNumToConsole(s, 10ULL);
  printf("\n");
  printf("t: ");
  PrintNumToConsole(t, 10ULL);
  printf("\n");
  if (!BigSub(s, t, order)) {
    ret = false;
    goto done;
  }
  printf("order: ");
  PrintNumToConsole(order, 10ULL);
  printf("\n");
done:
  return ret;
}

bool SimpleSchoofTest() {
  printf("SimpleSchoofTest()\n");
  return true;
  /*
    BigNum    small_order(2);
    BigNum    small_p(2, 19ULL);
    EccCurve  curve;

    // curve_poly= x^3+2x+1 (mod 19)
    if(!schoof(curve, small_order)) {
      printf("schoof failed\n");
      return false;
    }

    return true;
    extern EccKey   P256_Key;
    Polynomial curve_poly(8, 5, *P256_Key.c_.p_);
    if(!PolyFromCurve(P256_Key.c_, curve_poly)) {
      printf("PolyFromCurve failed\n");
      return false;
    }
    printf("curve prime: "); PrintNumToConsole(*P256_Key.c_.p_, 10ULL);
    printf("\n");
    curve_poly.Print();
    Compute_t_mod_2(Polynomial& curve_poly, uint64_t* result)
    Compute_t_mod_l(Polynomial& curve_poly, uint64_t l, uint64_t* result)
    schoof(EccCurve& curve, BigNum& order)
    return true;
   */
}

TEST(SimpleTest, SimpleTest) {
  EXPECT_TRUE(SimpleSchoofTest());
  EXPECT_TRUE(BsgsTest());
  EXPECT_TRUE(SimplePhiTest());
  EXPECT_TRUE(SimpleSymbolicTest());
}

DEFINE_string(log_file, "schooftest.log", "schooftest file name");

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
