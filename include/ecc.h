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
// File: ecc.h

#include "cryptotypes.h"
#include "keys.pb.h"
#include "bignum.h"

#ifndef _CRYPTO_ECC_H__
#define _CRYPTO_ECC_H__

class CurvePoint {
public:
  BigNum* x_;
  BigNum* y_;
  BigNum* z_;

        CurvePoint();
        CurvePoint(int size);
        CurvePoint(BigNum& x, BigNum& y);
        CurvePoint(CurvePoint& P);
        ~CurvePoint();
  bool  IsZero();
  void  Clear();
  void  MakeZero();
  bool  CopyFrom(CurvePoint& P);
  bool  CopyTo(CurvePoint& P);
  bool  Normalize(BigNum& p);
  bool  SerializePointToMessage(crypto_point_message&);
  bool  DeserializePointFromMessage(crypto_point_message&);
  void  PrintPoint();
};

class EccCurve {
public:
  BigNum* a_;
  BigNum* b_;
  BigNum* p_;

        EccCurve();
        EccCurve(int size);
        EccCurve(BigNum& a, BigNum& b, BigNum& p);
        ~EccCurve();
  void  Clear();
  bool  SerializeCurveToMessage(crypto_ecc_curve_message&);
  bool  DeserializeCurveFromMessage(crypto_ecc_curve_message&);
  void  PrintCurve();
};


bool InitEccCurves();
bool EccEmbed(EccCurve& c, BigNum& m, CurvePoint& P, int shift, int trys);
bool EccExtract(EccCurve& c, CurvePoint& P, BigNum& m, int shift);
bool EccNormalize(EccCurve& c, CurvePoint& P);
bool EccAdd(EccCurve& c, CurvePoint& P, CurvePoint& Q, CurvePoint& R);
bool EccSub(EccCurve& c, CurvePoint& P, CurvePoint& Q, CurvePoint& R);
bool EccDouble(EccCurve& c, CurvePoint& P, CurvePoint& R);
bool EccMult(EccCurve& c, CurvePoint& P, BigNum& x, CurvePoint& R);
bool FasterEccMult(EccCurve& c, CurvePoint& P, BigNum& x, CurvePoint& R);
bool ProjectiveToAffine(EccCurve& c, CurvePoint& P);
bool ProjectiveAdd(EccCurve& c, CurvePoint& P, CurvePoint& Q, CurvePoint& R);
bool ProjectiveDouble(EccCurve& c, CurvePoint& P, CurvePoint& R);
bool ProjectivePointMult(EccCurve& c, BigNum& x, CurvePoint& P, CurvePoint& R);

#endif

