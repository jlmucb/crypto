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
// File: polynomial.cc

#include "cryptotypes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "bignum.h"
using namespace std;

Polynomial::Polynomial(int size_num, num_c) {
  size_num_= 0;
  m_= NULL;
  num_c_= 0;
  c_= NULL;
}

Polynomial::Polynomial(int size_num, num_c) {
}

Polynomial::Polynomial(int size_num, num_c, BigNum& c) {
}

Polynomial::~Polynomial() {
}

int Polynomial::Degree() {
  return 0;
}

bool Polynomial::IsZero() {
  return false;
}

bool Polynomial::IsOne() {
  return false;
}

bool Polynomial::CopyTo(Polynomial& a) {
  return false;
}

bool Polynomial::CopyFrom(Polynomial& a) {
  return false;
}

bool Polynomial::MultiplyBy(BigNum& n) {
  return false;
}

bool Polynomial::AddTo(BigNum& n) {
  return false;
}

void Polynomial::Print(bool small) {
}

bool PolyIsEqual(Polynomial& a, Polynomial& b) {
  return false;
}

bool PolyAdd(Polynomial& a, Polynomial& b) {
  return false;
}

bool PolySub(Polynomial& a, Polynomial& b) {
  return false;
}

bool PolyMult(Polynomial& a, Polynomial& b) {
  return false;
}

bool PolyDiv(Polynomial& a, Polynomial& b) {
  return false;
}

bool ZeroPoly(Polynomial& a) {
  return false;
}

bool OnePoly(Polynomial& a) {
  return false;
}

bool PolyEuclid(Polynomial& a, Polynomial& b, Polynomial& q, Polynomial& r) {
  return false;
}

bool PolyExtendedGcd(Polynomial& a, Polynomial& b, Polynomial& x, Polynomial& y, 
                     Polynomial& g) {
  return false;
}

