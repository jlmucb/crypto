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
// File: ecc_symbolic.cc

#include "cryptotypes.h"
#include "bignum.h"
#include "ecc.h"
#include "indeterminate.h"
#include "ecc_symbolic.h"

bool PolyFromCurve(EccCurve& curve, Polynomial& curve_poly) {
  Big_One.CopyTo(*curve_poly.c_[3]);
  curve.a_->CopyTo(*curve_poly.c_[1]);
  curve.b_->CopyTo(*curve_poly.c_[0]);
  curve.p_->CopyTo(*curve_poly.m_);
  return true;
}

bool RationalPolyFromCurve(EccCurve& curve, RationalPoly** curve_rational) {
  // TODO
  return true;
}

bool RationalPolyNegate(RationalPoly& a) {
  int i;
  for (i = 0; i < a.top_->num_c_; i++) {
    a.top_->c_[i]->ToggleSign();
    BigModNormalize(*a.top_->c_[i], *a.top_->m_);
  }
  return true;
}

bool MakeSymbolicIdentity(RationalPoly& x, RationalPoly& y) {
  OnePoly(*x.top_);
  OnePoly(*x.bot_);
  ZeroPoly(*y.bot_);
  OnePoly(*y.top_);
  return true;
}

bool IsSymbolicIdentity(RationalPoly& x, RationalPoly& y) {
  return !y.top_->IsZero() && y.bot_->IsZero();
}

//  In the symbolic computations, we assume P=(r(x), yq(x)) but that the
//  y is surpressed in the representation of the point as a polynomial
//  (r1(x), r2(x)).  r(x) and q(x) are ratio's of polynomials.
//  Our data type for these ratios is rationalpoly.
//  Surpressing the y in the representation of points saves us
//  from having to do multi-variate polynomial caclulations.
//  We have to be careful, however, in the calculations to
//  remember the implicit y.

//  Ecc symbolic arithmetic
//
//  Powers of y bigger than 1 can be reduced mod the curve x^3+ax+b (mod p)
//    for elliptic curves.
//
//  Inputs are all rational polys.
//  P= (in1x, y in1y) and Q=(in2x, y in2y).
//  m= y ((in2y-in1y)/(in2x-in1x) or (3in1x^2+a)/2y.
//  m^2= y^2 ((in2y-in1y)/(in2x-in1x))^2 =
//    curve_x_poly((in2y-in1y)/(in2x-in1x))^2.
//  P+Q= (outx, y outy), where
//    outx= m^2-in1x-in2x,  and
//    outy= m (in1x-outx) - in1y.
//  This is sort of confusing but that's the way it is.

bool EccSymbolicAdd(Polynomial& curve_poly, RationalPoly& in1_x,
                    RationalPoly& in1_y, RationalPoly& in2_x,
                    RationalPoly& in2_y, RationalPoly& out_x,
                    RationalPoly& out_y) {
#ifdef DEBUGSYMBOLICADD
  printf("EccSymbolicAdd\nin1: ");
  printf("[");
  in1_x.Print(true);
  printf(", ");
  in1_y.Print(true);
  printf("]\n");
  printf("in2: ");
  printf("[");
  in2_x.Print(true);
  printf(", ");
  in2_y.Print(true);
  printf("]\n");
  printf("curve_poly: ");
  curve_poly.Print(true);
  printf("\n");
#endif

  if (IsSymbolicIdentity(in1_x, in1_y)) {
    out_x.CopyFrom(in2_x);
    out_y.CopyFrom(in2_y);
    return true;
  }
  if (IsSymbolicIdentity(in2_x, in2_y)) {
    out_x.CopyFrom(in1_x);
    out_y.CopyFrom(in1_y);
    return true;
  }

  RationalPoly slope(in1_x.top_->size_num_, out_x.top_->num_c_,
                     *in1_x.top_->m_);
  RationalPoly slope_squared(in1_x.top_->size_num_, out_x.top_->num_c_,
                             *in1_x.top_->m_);
  RationalPoly t1(in1_x.top_->size_num_, out_x.top_->num_c_, *in1_x.top_->m_);
  RationalPoly t2(in1_x.top_->size_num_, out_x.top_->num_c_, *in1_x.top_->m_);
  Polynomial a(in1_x.top_->size_num_, out_x.top_->num_c_, *in1_x.top_->m_);
  Polynomial r1(in1_x.top_->size_num_, out_x.top_->num_c_, *in1_x.top_->m_);
  Polynomial r2(in1_x.top_->size_num_, out_x.top_->num_c_, *in1_x.top_->m_);

  //  if P==Q
  //    slope= (3in1_x^2+a)/(2(in1_y)y)= y((3in1_x^2+a)/(2 in1_y curve_poly))
  //  otherwise
  //    slope= y ((in2_y-in1_y)/(in2_x-in1_x)
  if (RationalIsEqual(in1_x, in2_x)) {
    if (RationalIsEqual(in1_y, in2_y)) {
      if (!RationalMult(in1_x, in1_x, t1)) return false;
      if (!MultiplyPolyByMonomial(*t1.top_, 0, Big_Three, r1)) return false;
      a.c_[0]->CopyFrom(*curve_poly.c_[1]);
      if (!PolyAdd(r1, a, *t1.top_)) return false;
      curve_poly.CopyTo(*t1.bot_);
      if (!in1_y.CopyTo(t2)) return false;
      if (!MultiplyPolyByMonomial(*t2.top_, 0, Big_Two, r1)) return false;
      r1.CopyTo(*t2.top_);
      if (!RationalDiv(t1, t2, slope)) return false;
    } else {
      if (!MakeSymbolicIdentity(out_x, out_y)) return false;
#ifdef DEBUGSYMBOLICADD
      printf("returning identity\n");
#endif
      return true;
    }
  } else {
    if (!RationalSub(in2_y, in1_y, t1)) return false;
    if (!RationalSub(in2_x, in1_x, t2)) return false;
    if (!RationalDiv(t1, t2, slope)) return false;
  }
#ifdef DEBUGSYMBOLICADD
  printf("slope: ");
  slope.Print(true);
  printf("\n");
#endif

  //  Compute slope^2
  //    slope_squared= slope*slope*curve_x_poly
  if (!RationalMult(slope, slope, slope_squared)) return false;
  if (!PolyMult(*slope_squared.top_, curve_poly, r1)) return false;
  if (!r1.CopyTo(*slope_squared.top_)) return false;
  if (!slope_squared.Reduce()) return false;

#ifdef DEBUGSYMBOLICADD
  printf("slope_squared: ");
  slope_squared.Print(true);
  printf("\n");
#endif

  //  P+Q= (out_x, y out_y), where
  //    out_x= slope^2-in1_x-in2_x,  and
  //    out_y= slope (in1_x-out_x) - in1_y.
  if (!RationalSub(slope_squared, in1_x, t2)) return false;
  if (!RationalSub(t2, in2_x, out_x)) return false;
  if (!RationalSub(in1_x, out_x, t2)) return false;
  if (!RationalMult(t2, slope, t1)) return false;
  if (!RationalSub(t1, in1_y, out_y)) return false;

#ifdef DEBUGSYMBOLICADD
  printf("EccSymbolicAdd, returning: ");
  printf("[");
  out_x.Print(true);
  printf(", ");
  out_y.Print(true);
  printf("]\n");
#endif
  return true;
}

bool EccSymbolicSub(Polynomial& curve_poly, RationalPoly& in1_x,
                    RationalPoly& in1_y, RationalPoly& in2_x,
                    RationalPoly& in2_y, RationalPoly& out_x,
                    RationalPoly& out_y) {
  RationalPoly neg_y(in1_x.top_->size_num_, in1_x.top_->num_c_,
                     *in1_x.top_->m_);
  neg_y.CopyFrom(in2_y);
  if (!RationalPolyNegate(neg_y)) return false;
  return EccSymbolicAdd(curve_poly, in1_x, in1_y, in2_x, neg_y, out_x, out_y);
}

//  Usual power of two reduction
bool EccSymbolicMult(Polynomial& curve_poly, BigNum& m, RationalPoly& in_x,
                     RationalPoly& in_y, RationalPoly& out_x,
                     RationalPoly& out_y) {
  int k = BigHighBit(m);
  int i;
  RationalPoly double_point_x(in_x.top_->size_num_, in_x.top_->num_c_,
                              *in_x.top_->m_);
  RationalPoly double_point_y(in_x.top_->size_num_, in_x.top_->num_c_,
                              *in_x.top_->m_);
  RationalPoly accum_point_x(in_x.top_->size_num_, in_x.top_->num_c_,
                             *in_x.top_->m_);
  RationalPoly accum_point_y(in_x.top_->size_num_, in_x.top_->num_c_,
                             *in_x.top_->m_);
  RationalPoly t1(in_x.top_->size_num_, in_x.top_->num_c_, *in_x.top_->m_);
  RationalPoly t2(in_x.top_->size_num_, in_x.top_->num_c_, *in_x.top_->m_);
  RationalPoly t_double_x(in_x.top_->size_num_, in_x.top_->num_c_,
                          *in_x.top_->m_);
  RationalPoly t_double_y(in_x.top_->size_num_, in_x.top_->num_c_,
                          *in_x.top_->m_);

#ifdef DEBUGSYMBOLICMULT
  printf("EccSymbolicMult\n");
  PrintNumToConsole(m, 10ULL);
  printf("[");
  in_x.Print(true);
  printf(", ");
  in_y.Print(true);
  printf("]\n");
  printf("Curve_poly: ");
  curve_poly.Print(true);
  printf("\n");
#endif

  if (!MakeSymbolicIdentity(accum_point_x, accum_point_y)) {
    return false;
  }
  in_x.CopyTo(double_point_x);
  in_y.CopyTo(double_point_y);
  for (i = 1; i < k; i++) {
    if (BigBitPositionOn(m, i)) {
      if (!EccSymbolicAdd(curve_poly, double_point_x, double_point_y,
                          accum_point_x, accum_point_y, t1, t2)) {
        printf("EccSymbolicAdd 1 fails\n");
        return false;
      }
      t1.CopyTo(accum_point_x);
      t2.CopyTo(accum_point_y);
    }
#ifdef DEBUGSYMBOLICMULT
    printf("double_point: ");
    printf("[");
    double_point_x.Print(true);
    printf(", ");
    double_point_y.Print(true);
    printf("]\n");
    printf("accum_point: ");
    printf("[");
    accum_point_x.Print(true);
    printf(", ");
    accum_point_y.Print(true);
    printf("]\n");
#endif

    if (!EccSymbolicAdd(curve_poly, double_point_x, double_point_y,
                        double_point_x, double_point_y, t_double_x,
                        t_double_y)) {
      printf("EccSymbolicAdd 2 fails\n");
      return false;
    }
    double_point_x.CopyFrom(t_double_x);
    double_point_y.CopyFrom(t_double_y);
  }
  if (BigBitPositionOn(m, i)) {
#ifdef DEBUGSYMBOLICMULT
    printf("double_point 2: ");
    printf("[");
    double_point_x.Print(true);
    printf(", ");
    double_point_y.Print(true);
    printf("]\n");
    printf("accum_point 2: ");
    printf("[");
    accum_point_x.Print(true);
    printf(", ");
    accum_point_y.Print(true);
    printf("]\n");
#endif
    if (!EccSymbolicAdd(curve_poly, accum_point_x, accum_point_y,
                        double_point_x, double_point_y, t_double_x, t_double_y))
      return false;
    out_x.CopyFrom(t_double_x);
    out_y.CopyFrom(t_double_y);
#ifdef DEBUGSYMBOLICMULT
    printf("t_double_x: ");
    printf("[");
    t_double_x.Print(true);
    printf(", ");
    t_double_y.Print(true);
    printf("]\n");
#endif
    return true;
  }
  out_x.CopyFrom(accum_point_x);
  out_y.CopyFrom(accum_point_y);
  return true;
}

bool ReducedEccSymbolicAdd(Polynomial& curve_poly, Polynomial& mod_poly,
                           RationalPoly& in1_x, RationalPoly& in1_y,
                           RationalPoly& in2_x, RationalPoly& in2_y,
                           RationalPoly& out_x, RationalPoly& out_y) {
#ifdef DEBUGREDUCEDSYMBOLICADD
  printf("ReducedEccSymbolicAdd\nin1: ");
  printf("[");
  in1_x.Print(true);
  printf(", ");
  in1_y.Print(true);
  printf("]\n");
  printf("in2: ");
  printf("[");
  in2_x.Print(true);
  printf(", ");
  in2_y.Print(true);
  printf("]\n");
  printf("(mod ");
  mod_poly.Print(true);
  printf(")\n");
#endif

  if (mod_poly.IsZero()) return false;
  if (IsSymbolicIdentity(in1_x, in1_y)) {
    out_x.CopyFrom(in2_x);
    out_y.CopyFrom(in2_y);
    return true;
  }
  if (IsSymbolicIdentity(in2_x, in2_y)) {
    out_x.CopyFrom(in1_x);
    out_y.CopyFrom(in1_y);
    return true;
  }
  RationalPoly slope(in1_x.top_->size_num_, out_x.top_->num_c_,
                     *in1_x.top_->m_);
  RationalPoly slope_squared(in1_x.top_->size_num_, out_x.top_->num_c_,
                             *in1_x.top_->m_);
  RationalPoly t1(in1_x.top_->size_num_, out_x.top_->num_c_, *in1_x.top_->m_);
  RationalPoly t2(in1_x.top_->size_num_, out_x.top_->num_c_, *in1_x.top_->m_);
  Polynomial a(in1_x.top_->size_num_, out_x.top_->num_c_, *in1_x.top_->m_);
  Polynomial r1(in1_x.top_->size_num_, out_x.top_->num_c_, *in1_x.top_->m_);
  Polynomial r2(in1_x.top_->size_num_, out_x.top_->num_c_, *in1_x.top_->m_);

  //  if P==Q
  //    slope= y (3in1_x^2+a)/(2(in1_y)(curve_poly))
  //  otherwise
  //    slope= y ((in2_y-in1_y)/(in2_x-in1_x)
  if (RationalIsEqual(in1_x, in2_x)) {
    if (RationalIsEqual(in1_y, in2_y)) {
      if (!RationalMult(in1_x, in1_x, t1)) return false;
      if (!MultiplyPolyByMonomial(*t1.top_, 0, Big_Three, r1)) return false;
      a.c_[0]->CopyFrom(*curve_poly.c_[1]);
      if (!PolyAdd(r1, a, *t1.top_)) return false;
      curve_poly.CopyTo(*t1.bot_);
      if (!in1_y.CopyTo(t2)) return false;
      if (!MultiplyPolyByMonomial(*t2.top_, 0, Big_Two, r1)) return false;
      r1.CopyTo(*t2.top_);
      if (!RationalDiv(t1, t2, slope)) return false;
    } else {
      if (!MakeSymbolicIdentity(out_x, out_y)) return false;
      return true;
    }
  } else {
    if (!RationalSub(in2_y, in1_y, t1)) return false;
    if (!RationalSub(in2_x, in1_x, t2)) return false;
    if (!RationalDiv(t1, t2, slope)) return false;
  }
  if (!ReduceModPoly(*slope.top_, mod_poly, r1)) return false;
  if (!r1.CopyTo(*slope.top_)) return false;
  if (!ReduceModPoly(*slope.bot_, mod_poly, r1)) return false;
  if (!r1.CopyTo(*slope.bot_)) return false;
#ifdef DEBUGREDUCEDSYMBOLICADD
  printf("ReducedEccSymbolicAdd slope: ");
  slope.Print(true);
  printf("\n");
#endif

  //  Compute slope^2
  //    slope_squared= slope*slope*curve_x_poly
  if (!RationalMult(slope, slope, slope_squared)) return false;
  if (!PolyMult(*slope_squared.top_, curve_poly, r1)) return false;
  if (!r1.CopyTo(*slope_squared.top_)) return false;
  if (!slope_squared.Reduce()) return false;

  if (!ReduceModPoly(*slope_squared.top_, mod_poly, r1)) return false;
  if (!r1.CopyTo(*slope_squared.top_)) return false;
  if (!ReduceModPoly(*slope_squared.bot_, mod_poly, r1)) return false;
  if (!r1.CopyTo(*slope_squared.bot_)) return false;

  //  P+Q= (out_x, y out_y), where
  //    out_x= slope^2-in1_x-in2_x,  and
  //    out_y= slope (in1_x-out_x) - in1_y.
  if (!RationalSub(slope_squared, in1_x, t2)) return false;
  if (!RationalSub(t2, in2_x, t1)) return false;
  if (!ReduceModPoly(*t1.top_, mod_poly, *out_x.top_)) return false;
  if (!ReduceModPoly(*t1.bot_, mod_poly, *out_x.bot_)) return false;
  if (!RationalSub(in1_x, out_x, t2)) return false;
  if (!RationalMult(t2, slope, t1)) return false;
  ZeroRational(t2);
  if (!RationalSub(t1, in1_y, t2)) return false;
  if (!ReduceModPoly(*t2.top_, mod_poly, *out_y.top_)) return false;
  if (!ReduceModPoly(*t2.bot_, mod_poly, *out_y.bot_)) return false;
  return true;
}

//#define DEBUGREDUCEDSYMBOLICMULT
//  Usual power of two reduction
bool ReducedEccSymbolicMult(Polynomial& curve_poly, Polynomial& mod_poly,
                            BigNum& n, RationalPoly& in_x, RationalPoly& in_y,
                            RationalPoly& out_x, RationalPoly& out_y) {
  int i;
  RationalPoly double_point_x(in_x.top_->size_num_, 4 * out_x.top_->num_c_,
                              *in_x.top_->m_);
  RationalPoly double_point_y(in_x.top_->size_num_, 4 * out_x.top_->num_c_,
                              *in_x.top_->m_);
  RationalPoly accum_point_x(in_x.top_->size_num_, 4 * out_x.top_->num_c_,
                             *in_x.top_->m_);
  RationalPoly accum_point_y(in_x.top_->size_num_, 4 * out_x.top_->num_c_,
                             *in_x.top_->m_);
  RationalPoly t1(in_x.top_->size_num_, 4 * out_x.top_->num_c_, *in_x.top_->m_);
  RationalPoly t2(in_x.top_->size_num_, 4 * out_x.top_->num_c_, *in_x.top_->m_);
  RationalPoly t_double_x(in_x.top_->size_num_, 4 * out_x.top_->num_c_,
                          *in_x.top_->m_);
  RationalPoly t_double_y(in_x.top_->size_num_, 4 * out_y.top_->num_c_,
                          *in_x.top_->m_);

#ifdef DEBUGREDUCEDSYMBOLICMULT
  printf("ReducedEccSymbolicMult\nin: ");
  PrintNumToConsole(n, 10ULL);
  printf("[");
  in_x.Print(true);
  printf(", ");
  in_y.Print(true);
  printf("]\n");
  printf("(mod  ");
  mod_poly.Print(true);
  printf(")\n");
#endif

  if (mod_poly.IsZero()) return false;
  if (!MakeSymbolicIdentity(accum_point_x, accum_point_y)) return false;
  in_x.CopyTo(double_point_x);
  in_y.CopyTo(double_point_y);

  BigNum m(n);
  if (n.IsNegative()) {
    m.ToggleSign();
    if (!RationalPolyNegate(double_point_y)) return false;
  }
  int k = BigHighBit(m);
  for (i = 1; i < k; i++) {
#ifdef DEBUGREDUCEDSYMBOLICMULT
    printf("double_point (1): [");
    double_point_x.Print(true);
    printf(", ");
    double_point_y.Print(true);
    printf("]\n");
    printf("accum_point (1): [");
    accum_point_x.Print(true);
    printf(", ");
    accum_point_y.Print(true);
    printf("]\n");
    printf("i %d, k: %d\n", i, k);
#endif

    if (BigBitPositionOn(m, i)) {
      if (!EccSymbolicAdd(curve_poly, double_point_x, double_point_y,
                          accum_point_x, accum_point_y, t1, t2)) {
        printf("EccSymbolicAdd 1 failed\n");
        return false;
      }
      if (!ReduceModPoly(*t1.top_, mod_poly, *accum_point_x.top_)) return false;
      if (!ReduceModPoly(*t1.bot_, mod_poly, *accum_point_x.bot_)) return false;
      if (!ReduceModPoly(*t2.top_, mod_poly, *accum_point_y.top_)) return false;
      if (!ReduceModPoly(*t2.bot_, mod_poly, *accum_point_y.bot_)) return false;
    }
    if (!EccSymbolicAdd(curve_poly, double_point_x, double_point_y,
                        double_point_x, double_point_y, t_double_x,
                        t_double_y)) {
      printf("EccSymbolicAdd 2 failed\n");
      return false;
    }
#ifdef DEBUGREDUCEDSYMBOLICMULT
    printf("double_point (3): 2[");
    double_point_x.Print(true);
    printf(", ");
    double_point_y.Print(true);
    printf("]= ");
    printf("[");
    t_double_x.Print(true);
    printf(", ");
    t_double_y.Print(true);
    printf("]\n");
#endif
    if (!ReduceModPoly(*t_double_x.top_, mod_poly, *double_point_x.top_))
      return false;
    if (!ReduceModPoly(*t_double_x.bot_, mod_poly, *double_point_x.bot_))
      return false;
    if (!ReduceModPoly(*t_double_y.top_, mod_poly, *double_point_y.top_))
      return false;
    if (!ReduceModPoly(*t_double_y.bot_, mod_poly, *double_point_y.bot_))
      return false;
  }
#ifdef DEBUGREDUCEDSYMBOLICMULT
  printf("i %d, k: %d\n", i, k);
  printf("double_point (2): [");
  double_point_x.Print(true);
  printf(", ");
  double_point_y.Print(true);
  printf("]\n");
  printf("accum_point (2): [");
  accum_point_x.Print(true);
  printf(", ");
  accum_point_y.Print(true);
  printf("]\n");
#endif
  if (BigBitPositionOn(m, i)) {
    if (!EccSymbolicAdd(curve_poly, accum_point_x, accum_point_y,
                        double_point_x, double_point_y, t_double_x, t_double_y))
      return false;
    if (!ReduceModPoly(*t_double_y.top_, mod_poly, *out_y.top_)) return false;
    if (!ReduceModPoly(*t_double_y.bot_, mod_poly, *out_y.bot_)) return false;
    if (!ReduceModPoly(*t_double_x.top_, mod_poly, *out_x.top_)) return false;
    if (!ReduceModPoly(*t_double_x.bot_, mod_poly, *out_x.bot_)) return false;
    return true;
  }
  if (!ReduceModPoly(*double_point_y.top_, mod_poly, *out_y.top_)) return false;
  if (!ReduceModPoly(*double_point_y.bot_, mod_poly, *out_y.bot_)) return false;
  if (!ReduceModPoly(*double_point_x.top_, mod_poly, *out_x.top_)) return false;
  if (!ReduceModPoly(*double_point_x.bot_, mod_poly, *out_x.bot_)) return false;
  return true;
}

bool ReducedRaisetoLargePower(Polynomial& in, BigNum& e, Polynomial& mod_poly,
                              Polynomial& out) {
  Polynomial double_point(out.size_num_, 2 * out.num_c_, *out.m_);
  Polynomial accum_point(out.size_num_, 2 * out.num_c_, *out.m_);
  Polynomial t1(out.size_num_, 2 * out.num_c_, *out.m_);
  Polynomial t2(out.size_num_, 2 * out.num_c_, *out.m_);
  int i;
  int k = BigHighBit(e);

  if (mod_poly.IsZero()) return false;
  double_point.CopyFrom(in);
  OnePoly(accum_point);
  for (i = 1; i < k; i++) {
    if (BigBitPositionOn(e, i)) {
      if (!PolyMult(double_point, accum_point, t1)) {
        printf("ReducedRaisetoLargePower, PolyMult 1 fails %d %d %d\n",
               double_point.Degree(), accum_point.Degree(), t1.Degree());
        return false;
      }
      if (!ReduceModPoly(t1, mod_poly, accum_point)) {
        printf("ReducedRaisetoLargePower, ReducePoly 1 fails\n");
        return false;
      }
    }
    if (!PolyMult(double_point, double_point, t1)) {
      printf("ReducedRaisetoLargePower, PolyMult 2 fails %d %d\n",
             double_point.Degree(), t1.Degree());
      return false;
    }
    if (!ReduceModPoly(t1, mod_poly, double_point)) {
      printf("ReducedRaisetoLargePower, ReducePoly 2 fails %d %d %d\n",
             t1.Degree(), mod_poly.Degree(), double_point.num_c_);
      return false;
    }
  }
  if (BigBitPositionOn(e, i)) {
    if (!PolyMult(double_point, accum_point, t1)) {
      printf("ReducedRaisetoLargePower, PolyMult 3 fails %d %d %d\n",
             double_point.Degree(), accum_point.Degree(), t1.Degree());
      return false;
    }
    if (!ReduceModPoly(t1, mod_poly, accum_point)) {
      printf("ReducedRaisetoLargePower, ReducePoly 3 fails\n");
      return false;
    }
  }
  accum_point.CopyTo(out);
  return true;
}

//  Since this is an endomorphism, the result is (r(x), yq(x)) and we return
//  out_x= r[x] and out_y= q(x).  So out_y should be multiplied by y to give the
//  answer
bool EccSymbolicMultEndomorphism(Polynomial& curve_poly, BigNum& m,
                                 Polynomial& mod_poly, RationalPoly& out_x,
                                 RationalPoly& out_y) {
  // m(x/1, 1/1) --> (out_x, out_y)
  RationalPoly x_rational(curve_poly.m_->Capacity(), mod_poly.num_c_ + 2,
                          *curve_poly.m_);
  RationalPoly y_rational(curve_poly.m_->Capacity(), mod_poly.num_c_ + 2,
                          *curve_poly.m_);
  ZeroRational(x_rational);
  OneRational(y_rational);
  x_rational.top_->c_[1]->value_[0] = 1ULL;
  x_rational.top_->c_[1]->Normalize();
  if (!ReducedEccSymbolicMult(curve_poly, mod_poly, m, x_rational, y_rational,
                              out_x, out_y)) {
    printf("ReducedEccSymbolicMult failed\n");
    return false;
  }
  return true;
}

//  Since this is an endomorphism, the result is (r(x), yq(x)) and we return
//  out_x= r[x] and out_y= q(x).  So out_y should be multiplied by y to give the
//  answer
bool EccSymbolicPowerEndomorphism(Polynomial& curve_poly, BigNum& e,
                                  Polynomial& mod_poly, RationalPoly& out_x,
                                  RationalPoly& out_y) {
  // out_x= x^e, out_y= curve_poly^(e-1)/2  reduced by curve_poly
  // set in RationalPolys with denominator 1
  Polynomial x_poly(curve_poly.m_->Capacity(), 4, *curve_poly.m_);
  Polynomial y_poly(curve_poly.m_->Capacity(), 4, *curve_poly.m_);
  BigNum e1(e.Capacity());
  BigNum t(e.Capacity());

#ifdef DEBUGSYMBOLICPOWERENDO
  printf(
      "EccSymbolicPowerEndomorphism, deg(curve_poly)= %d, deg(mod_poly)= %d\n",
      curve_poly.Degree(), mod_poly.Degree());
#endif

  ZeroPoly(x_poly);
  OnePoly(y_poly);
  x_poly.c_[1]->value_[0] = 1ULL;
  x_poly.c_[1]->Normalize();

  if (!BigUnsignedSub(e, Big_One, t)) return false;
  if (!BigShift(t, -1, e1)) return false;
  if (!ReducedRaisetoLargePower(x_poly, e, mod_poly, *out_x.top_)) return false;
  if (!ReducedRaisetoLargePower(curve_poly, e1, mod_poly, *out_y.top_))
    return false;
  OnePoly(*out_x.bot_);
  OnePoly(*out_y.bot_);
  return true;
}
