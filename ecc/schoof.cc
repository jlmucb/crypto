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


//  Ecc symbolic arithmetic
//
//  Power of y bigger than 1 can be reduced mod the curve x^3+ax+b (mod p)
//    for elliptic curves.
//
//  Inputs are all rational polys.  
//  P= (in1x, y in1y) and Q=(in2x, y in2y).
//  m= y ((in2y-in1y)/(in2x-in1x) or (3in1x^2+a)/2in1y.
//  m^2= y^2 ((in2y-in1y)/(in2x-in1x))^2 =
//    curve_x_poly((in2y-in1y)/(in2x-in1x))^2.
//  P+Q= (outx, y outy), where
//    outx= m^2-in1x-in2x,  and
//    outy= ((in2y-in1y)/(in2x-in1x))(in1x-outx) - in1y.
//  This is sort of confusing but that's the way it is.
bool EccSymbolicAdd(EccCurve& curve, RationalPoly& in1, RationalPoly& in2, RationalPoly& out) {
  return true;
}

bool EccSymbolicSub(EccCurve& curve, RationalPoly& in1, RationalPoly& in2, RationalPoly& out) {
  return true;
}

bool EccSymbolicMult(EccCurve& curve, BigNum& m, RationalPoly& in, RationalPoly& out) {
  return true;
}

//  Since this is an endomorphism, the result is (r(x), yq(x)) and we return
//  out_x= r[x] and out_y= q(x).  So out_y should be multiplied by y to give the answer
bool EccSymbolicMultEndomorphism(EccCurve& curve, BigNum& m, RationalPoly& out) {
  return true;
}

//  Since this is an endomorphism, the result is (r(x), yq(x)) and we return
//  out_x= r[x] and out_y= q(x).  So out_y should be multiplied by y to give the answer
bool EccSymbolicPowerEndomorphism(EccCurve& curve, BigNum& e, RationalPoly& out) {
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
//   Takes coefficients of short Weierstrauss parameters (a, b, p) and compute
//   the order of the group.
bool schoof(EccCurve& curve, BigNum& order) {
  return true;
}

