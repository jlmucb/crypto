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
// File: schoof.cc

#include "cryptotypes.h"
#include "bignum.h"
#include "ecc.h"
#include "indeterminate.h"

bool RationalPolyFromCurve(EccCurve& curve, RationalPoly** curve_poly) {
  int size_num= curve.a_->Capacity();
  int n= curve.a_->Capacity();

  if(n>size_num)
    size_num= n;
  *curve_poly= new RationalPoly(size_num, 5, *curve.p_);
  Big_One.CopyTo(*((*curve_poly)->c_[3]));
  curve.a_->CopyTo(*((*curve_poly)->c_[1]));
  curve.b_->CopyTo(*((*curve_poly)->c_[0]));
  return true;
}

bool RationalPolyNegate(RationalPoly& a) {
  int i;

  for(i=0; i<a.num_c_; i++) {
    a.c_[i]->ToggleSign();
    BigModNormalize(*a.c_[i], *a.m_);
  }
  return true;
}

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

bool EccSymbolicAdd(RationalPoly& curve_poly, RationalPoly& in1_x, RationalPoly& in1_y, 
                    RationalPoly& in2_x, RationalPoly& in2_y, 
                    RationalPoly& out_x, RationalPoly& out_y) {
  RationalPoly  slope(in1_x.top_->size_num_, in1_x.top_->num_c_, *in1_x.top_->m_);
  RationalPoly  slope_squared(in1_x.top_->size_num_, in1_x.top_->num_c_, *in1_x.top_->m_);
  RationalPoly  t1(in1_x.top_->size_num_, in1_x.top_->num_c_, *in1_x.top_->m_);
  RationalPoly  t2(in1_x.top_->size_num_, in1_x.top_->num_c_, *in1_x.top_->m_);
  RationalPoly  a(in1_x.top_->size_num_, in1_x.top_->num_c_, *in1_x.top_->m_);
  Polynomial    r1(in1_x.top_->size_num_, in1_x.top_->num_c_, *in1_x.top_->m_);

  //  if P==Q
  //    slope= y (3in1_x^2+a)/(2(in1_y)(curve_poly))
  //  otherwise
  //    slope= y ((in2_y-in1_y)/(in2_x-in1_x)
  if(RationalIsEqual(in1_x,in2_x) && RationalIsEqual(in1_y, in2_y)) {
    ZeroRational(a);
    a.top_->c_[0]->CopyFrom(*curve_poly.c_[1]);
    if(!RationalMult(in1_x, in1_x, t1))
      return false;
    if(!MultiplyPolyByMonomial(*t1.top_, 0, Big_Three, r1))
      return false;
    if(!r1.CopyTo(*t1.top_))
      return false;
    if(!RationalAdd(t1, a, t2))
      return false;
    if(!RationalMult(in1_y, curve_poly, t2))
      return false;
    if(!MultiplyPolyByMonomial(*t2.top_, 0, Big_Two, r1))
      return false;
    if(!r1.CopyTo(*t2.top_))
      return false;
    if(!RationalDiv(t1, t2, slope))
      return false;
  } else {
    if(!RationalSub(in1_y, in1_y, t1))
      return fasle;
    if(!RationalSub(in1_x, in1_x, t2))
      return fasle;
    if(!RationalDiv(t1, t2, slope))
      return fasle;
  }

  //  Compute slope^2
  //    slope_squared= slope*slope*curve_x_poly
  if(!RationalMult(slope, slope, t2))
    return false;
  if(!RationalMult(t2, curve_poly, slope_squared))
    return false;

  //  P+Q= (out_x, y out_y), where
  //    out_x= slope^2-in1_x-in2_x,  and
  //    out_y= slope (in1_x-out_x) - in1_y.
  if(!RationalSub(slope_squared, in1_x, t2))
    return false;
  if(!RationalSub(t2, in2_x, out_x))
    return false;
  if(!RationalSub(in1_x, out_x, t2))
    return false;
  if(!RationalMult(t2, slope, t1))
    return false;
  if(!RationalSub(t1, in1_y, out_y))
    return false;
  return true;
}

bool EccSymbolicSub(RationalPoly& curve_poly, 
                    RationalPoly& in1_x, RationalPoly& in1_y,
                    RationalPoly& in2_x, RationalPoly& in2_y,
                    RationalPoly& out_x, RationalPoly& out_y) {
  // negate in2 and call EccSymbolicAdd
  return true;
}

//  Usual power of two reduction
bool EccSymbolicMult(RationalPoly& curve_poly, BigNum& m, 
                     RationalPoly& in_x, RationalPoly& in_y,
                     RationalPoly& out_x, RationalPoly& out_y) {
  return true;
}

//  Since this is an endomorphism, the result is (r(x), yq(x)) and we return
//  out_x= r[x] and out_y= q(x).  So out_y should be multiplied by y to give the answer
bool EccSymbolicMultEndomorphism(RationalPoly& curve_poly, BigNum& m, 
                                 RationalPoly& out_x, RationalPoly& out_y) {
  return true;
}

//  Since this is an endomorphism, the result is (r(x), yq(x)) and we return
//  out_x= r[x] and out_y= q(x).  So out_y should be multiplied by y to give the answer
bool EccSymbolicPowerEndomorphism(RationalPoly& curve_poly, BigNum& e, 
                                  RationalPoly& out_x, RationalPoly& out_y) {
  return true;
}

//  0. Precompute division polynomials
//  1. Pick S= {p[1], ..., p[k]: p[1]*p[2}*...*p[k]>4(q^(1/4)), q not in S
//  2. for p[1]=2, t=0 (2) iff (x^3+ax+b, x^q-x)= 1
//  3. for each odd l in S
//    3a.
//      q[l]= q (mod l), |q[l]|<l/2
//    3b.
//      Compute (x', y')= (x^(q^2), y^(q^2)) + q[l] (x,y)
//    3c. for j= 1,2,...(l-1)/2
//      3c(i).  Compute x[j], (x[j], y[j])= j(x,y)
//      3c(ii). If (x'-x[j]^q)= 0 (mod phi[l](x)), goto iii
//              If not, try next j; if all tried, goto 3d
//      3c(iii). Compute y' and y[j].  If (y'-y[j])/y= 0 (mod (phi[l](x))
//                                  then t= j (mod l), if not
//                                       t= -j (mod l)
//    3d. Let w^2= q (mod l).  If no such w, t=0 (mod l)
//    3e. If (gcd(numerator(x^q-x[w]), phi[l](x))= 1, t= 0 (mod l)
//          otherwise, compute (gcd(numerator(y^q-y[w]), phi[l](x))
//           if this is 1, t= 2w (mod l), otherwise, t= -2w (mod l)
//  4. User CRT to compute t, #E(q)= q+1-t, with t in right range for Hasse

//  In the symbolic computations, we assume P=(r(x), yq(x)) but that the
//  y is surpressed in the representation of the point as a polynomial
//  (r1(x), r2(x)).  r(x) and q(x) are ratio's of polynomials.
//  Our data type for these ratios is rationalpoly.
//  Surpressing the y in the representation of points saves us
//  from having to do multi-variate polynomial caclulations.
//  We have to be careful, however, in the calculations to
//  remember the implicit y.

//  Initialize phi functions
//  Free phi function

bool InitPhi() {
  return true;
}

bool FreePhi() {
  return true;
}

//  computemodulo2
//  computemodulop

//  compute order given value mod p[i], i=1,2,...,n

//  schoof
//   Takes coefficients of short Weierstrauss curves and compute
//   the order of the elliptic curve group.
bool schoof(EccCurve& curve, BigNum& order) {
  return true;
}

