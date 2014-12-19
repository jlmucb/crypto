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
// File: rational.cc

#include "cryptotypes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
using namespace std;
#include "bignum.h"
#include "indeterminate.h"


RationalPoly::RationalPoly(int size_num, int num_c) {
  top_= NULL;
  bot_= NULL;
}

RationalPoly::RationalPoly(int size_num, int num_c, BigNum& c) {
}

RationalPoly::~RationalPoly() {
}

int RationalPoly::Degree() {
  return 0;
}

bool RationalPoly::IsZero() {
  return false;
}

bool RationalPoly::IsOne() {
  return false;
}

bool RationalPoly::CopyTo(RationalPoly& a) {
  return false;
}

bool RationalPoly::CopyFrom(RationalPoly& a) {
  return false;
}

void RationalPoly::Print(bool small) {
}

bool RationalIsEqual(RationalPoly& a, RationalPoly& b) {
  return false;
}

bool RationaAdd(RationalPoly& a, RationalPoly& b) {
  return false;
}

bool RationaSub(RationalPoly& a, RationalPoly& b) {
  return false;
}

bool RationaMult(RationalPoly& a, RationalPoly& b) {
  return false;
}

bool RationaDiv(RationalPoly& a, RationalPoly& b) {
  return false;
}

bool ZeroRationa(RationalPoly& a) {
  return false;
}

bool OneRationa(RationalPoly& a) {
  return false;
}

