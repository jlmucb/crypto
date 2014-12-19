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
#include "indeterminate.h"
using namespace std;

Polynomial::Polynomial(int size_num, int num_c) {
  int i;

  m_= new BigNum(size_num);

  c_= new BigNum* [num_c];
  for(i= 0; i<num_c; i++)
    c_[i]= new BigNum(size_num);
  num_c_= num_c;
  size_num_= size_num;
  num_c_= num_c;
}

Polynomial::Polynomial(int size_num, int num_c, BigNum& c) {
  int i;

  m_= new BigNum(c);
  c_= new BigNum* [num_c];
  for(i= 0; i<num_c; i++)
    c_[i]= new BigNum(size_num);
  num_c_= num_c;
  size_num_= size_num;
  num_c_= num_c;
}

Polynomial::~Polynomial() {
  int i;
  for(i=0; i<num_c_; i++) {
    if(c_[i]!=NULL)
      delete c_[i];
    c_[i]= NULL;
  }
  if(m_!=NULL)
    delete m_;
  m_= NULL;
  size_num_= 0;
  num_c_= 0;
}

int Polynomial::Degree() {
  int i;

  for(i=(num_c_-1); i>=0;i--) {
    if(!c_[i]->IsZero())
      return i;
  }
  return -1; 
}

bool Polynomial::IsZero() {
  return Degree()==(-1);
}

bool Polynomial::IsOne() {
  if(Degree()!=0)
    return false;
  return c_[0]->IsOne();
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
  int i;

  for(i=(num_c_-1); i>0;i--) {
   if(small) {
    if(!c_[i]->IsZero())
      printf("%lld x**%d +", c_[i]);
    } else {
    }
  }
  if(small) {
      printf("%lld", c_[0]);
  } else {
  }
}

bool PolyIsEqual(Polynomial& a, Polynomial& b) {
  if(a.Degree()!=b.Degree())
    return false;
  int i;

  for(i=(a.num_c_-1); i>=0;i--) {
    if(BigCompare(*a.c_[i], *b.c_[i])!=0)
      return false;
  }
  return true;  
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

