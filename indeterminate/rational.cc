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
  top_= new Polynomial(size_num, num_c);
  bot_= new Polynomial(size_num, num_c);
}

RationalPoly::RationalPoly(int size_num, int num_c, BigNum& c) {
  top_= new Polynomial(size_num, num_c, c);
  bot_= new Polynomial(size_num, num_c, c);
}

RationalPoly::RationalPoly(int size_num, int num_c, BigNum& c, Polynomial& t, Polynomial& b) {
  top_= new Polynomial(size_num, num_c, c);
  bot_= new Polynomial(size_num, num_c, c);
  top_->CopyFrom(t);
  bot_->CopyFrom(b);
}

RationalPoly::~RationalPoly() {
  if(top_!=nullptr) {
    delete top_;
    top_= nullptr;
  }
  if(bot_!=nullptr) {
    delete bot_;
    bot_= nullptr;
  }
}

int RationalPoly::Degree() {
  int deg_num= top_->Degree();
  int deg_den= bot_->Degree();
  if(deg_num>deg_den)
    return deg_num;
  return deg_den;
}

bool RationalPoly::IsZero() {
  if(top_->IsZero() && !bot_->IsZero())
    return true;
  return false;
}

bool RationalPoly::IsOne() {
  if(top_->IsOne() && bot_->IsOne())
    return true;
  return false;
}

bool RationalPoly::CopyTo(RationalPoly& a) {
  if(!top_->CopyTo(*a.top_))
    return false;
  if(!bot_->CopyTo(*a.bot_))
    return false;
  return true;
}

bool RationalPoly::CopyFrom(RationalPoly& a) {
  return a.CopyTo(*this);
}

void RationalPoly::Print(bool small) {
  printf("[");
  top_->Print(small);
  printf("]/[");
  bot_->Print(small);
  printf("]");
}

bool RationalIsEqual(RationalPoly& a, RationalPoly& b) {
  int n= a.Degree()+b.Degree()+2;
  Polynomial  x(a.top_->size_num_, n, *a.top_->m_);
  Polynomial  y(a.top_->size_num_, n, *a.top_->m_);
  if(!a.Reduce())
    return false;
  if(!b.Reduce())
    return false;
  if(!PolyMult(*a.top_, *b.bot_, x))
    return false;
  if(!PolyMult(*b.top_, *a.bot_, y))
    return false;
  return PolyIsEqual(x,y);
}

bool RationalAdd(RationalPoly& a, RationalPoly& b, RationalPoly& c) {
  int n= a.Degree();
  int m= b.Degree();
  if(m>n)
    n= m;
  n= 2*n+2;
  Polynomial  t1(a.top_->size_num_, n, *a.top_->m_);
  Polynomial  t2(a.top_->size_num_, n, *a.top_->m_);
  if(!PolyMult(*a.bot_, *b.bot_, *c.bot_))
    return false;
  if(!PolyMult(*a.top_, *b.bot_, t1))
    return false;
  if(!PolyMult(*b.top_, *a.bot_, t2))
    return false;
  if(!PolyAdd(t1, t2, *c.top_))
    return false;
  return c.Reduce();
}

bool RationalSub(RationalPoly& a, RationalPoly& b, RationalPoly& c) {
  int n= a.Degree();
  int m= b.Degree();
  if(m>n)
    n= m;
  n= 2*n+2;
  Polynomial  t1(a.top_->size_num_, n, *a.top_->m_);
  Polynomial  t2(a.top_->size_num_, n, *a.top_->m_);

  if(!PolyMult(*a.bot_, *b.bot_, *c.bot_))
    return false;
  if(!PolyMult(*a.top_, *b.bot_, t1))
    return false;
  if(!PolyMult(*b.top_, *a.bot_, t2))
    return false;
  if(!PolySub(t1, t2, *c.top_))
    return false;
  return c.Reduce();
}

bool RationalPoly::Reduce() {
  int n= 2*Degree()+2;
  Polynomial  x(top_->size_num_, n, *top_->m_);
  Polynomial  y(top_->size_num_, n, *top_->m_);
  Polynomial  g(top_->size_num_, n, *top_->m_);

  if(bot_->IsZero() || top_->IsZero())
    return true;
  if(!PolyExtendedGcd(*top_, *bot_, x, y, g)) 
    return false;
  if(g.Degree()==0)
    return true;
  ZeroPoly(x);
  ZeroPoly(y);
  if(!PolyEuclid(*top_, g, x, y))
    return false;
  top_->CopyFrom(x);
  ZeroPoly(x);
  ZeroPoly(y);
  if(!PolyEuclid(*bot_, g, x, y))
    return false;
  bot_->CopyFrom(x);
  return true;
}

bool RationalMult(RationalPoly& a, RationalPoly& b, RationalPoly& c) {
  if(!PolyMult(*a.top_, *b.top_, *c.top_))
    return false;
  if(!PolyMult(*a.bot_, *b.bot_, *c.bot_))
    return false;
  return c.Reduce();
}

bool RationalDiv(RationalPoly& a, RationalPoly& b, RationalPoly& c) {
  if(!PolyMult(*a.top_, *b.bot_, *c.top_))
    return false;
  if(!PolyMult(*a.bot_, *b.top_, *c.bot_))
    return false;
  return c.Reduce();
}

bool ZeroRational(RationalPoly& a) {
  if(!ZeroPoly(*a.top_))
    return false;
  if(!OnePoly(*a.bot_))
    return false;
  return true;
}

bool OneRational(RationalPoly& a) {
  if(!OnePoly(*a.top_))
    return false;
  if(!OnePoly(*a.bot_))
    return false;
  return true;
}

