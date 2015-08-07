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
// File: bignum.h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <memory>
#include <iostream>

#include "cryptotypes.h"
#include "bignum.h"

#ifndef _CRYPTO_INDETERMINATE_H__
#define _CRYPTO_INDETERMINATE_H__

using std::string;

class Polynomial {
 public:
  int size_num_;
  BigNum* m_;
  int num_c_;
  BigNum** c_;

  Polynomial(int size_num, int num_c);
  Polynomial(int size_num, int num_c, BigNum& c);
  ~Polynomial();

  int Degree();
  bool IsZero();
  bool IsOne();
  bool CopyTo(Polynomial& a);
  bool CopyFrom(Polynomial& a);
  void Print(bool small = false);
};

class monomial {
 public:
  int d_;
  BigNum* n_;

  monomial();
  monomial(int d, int size, uint64_t v);
  ~monomial();
};

Polynomial* MakePoly(int size_num, int num_c, int n, monomial* m);

class RationalPoly {
 public:
  Polynomial* top_;
  Polynomial* bot_;

  RationalPoly(int size_num, int num_c);
  RationalPoly(int size_num, int num_c, BigNum& c);
  RationalPoly(int size_num, int num_c, BigNum& c, Polynomial& t,
               Polynomial& b);
  ~RationalPoly();

  int Degree();
  bool Reduce();
  bool IsZero();
  bool IsOne();
  bool CopyTo(RationalPoly& a);
  bool CopyFrom(RationalPoly& a);
  void Print(bool small = false);
};

bool PolyIsEqual(Polynomial& a, Polynomial& b);
bool PolyAdd(Polynomial& a, Polynomial& b, Polynomial& c);
bool PolySub(Polynomial& a, Polynomial& b, Polynomial& c);
bool PolyMult(Polynomial& a, Polynomial& b, Polynomial& c);
bool MultiplyPolyByMonomial(Polynomial& a, int d, BigNum& n, Polynomial& r);
bool ZeroPoly(Polynomial& a);
bool OnePoly(Polynomial& a);
bool PolyEuclid(Polynomial& a, Polynomial& b, Polynomial& q, Polynomial& r);
bool PolyExtendedGcd(Polynomial& a, Polynomial& b, Polynomial& x, Polynomial& y,
                     Polynomial& g);
bool ReduceModPoly(Polynomial& a, Polynomial& m, Polynomial& r);

bool RationalIsEqual(RationalPoly& a, RationalPoly& b);
bool RationalAdd(RationalPoly& a, RationalPoly& b, RationalPoly& c);
bool RationalSub(RationalPoly& a, RationalPoly& b, RationalPoly& c);
bool RationalMult(RationalPoly& a, RationalPoly& b, RationalPoly& c);
bool RationalDiv(RationalPoly& a, RationalPoly& b, RationalPoly& c);
bool ZeroRational(RationalPoly& a);
bool OneRational(RationalPoly& a);

#endif
