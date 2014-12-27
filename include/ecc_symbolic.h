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
// File: ecc_symbolic.h


#ifndef ECC_SYMBOLIC__H_
#define ECC_SYMBOLIC__H_

#include "cryptotypes.h"
#include "bignum.h"
#include "ecc.h"
#include "indeterminate.h"

bool PolyFromCurve(EccCurve& curve, Polynomial** curve_poly);
bool RationalPolyFromCurve(EccCurve& curve, RationalPoly** curve_rational);
bool RationalPolyNegate(RationalPoly& a);
bool MakeSymbolicIdentity(RationalPoly& x, RationalPoly& y);
bool IsSymbolicIdentity(RationalPoly& x, RationalPoly& y);
bool EccSymbolicAdd(Polynomial& curve_poly, RationalPoly& in1_x, RationalPoly& in1_y, 
                    RationalPoly& in2_x, RationalPoly& in2_y, 
                    RationalPoly& out_x, RationalPoly& out_y);
bool EccSymbolicSub(Polynomial& curve_poly, RationalPoly& in1_x, RationalPoly& in1_y,
                    RationalPoly& in2_x, RationalPoly& in2_y,
                    RationalPoly& out_x, RationalPoly& out_y);
bool EccSymbolicMult(Polynomial& curve_poly, BigNum& m,
                     RationalPoly& in_x, RationalPoly& in_y,
                     RationalPoly& out_x, RationalPoly& out_y);
bool RaisetoLargePower(RationalPoly& inx, RationalPoly& iny, BigNum& e,
                       Polynomial& curve_poly, Polynomial& mod_poly,
                       RationalPoly& outx, RationalPoly& outy);
bool EccSymbolicPowerEndomorphism(Polynomial& curve_poly, BigNum& e, 
                                  RationalPoly& out_x, RationalPoly& out_y);
bool EccSymbolicMultEndomorphism(Polynomial& curve_poly, BigNum& m, 
                                 RationalPoly& out_x, RationalPoly& out_y);
#endif
