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

inline int max(int a, int b) {
  if(a>b)
    return a;
  return b;
}

monomial::monomial() {
  d_= 0;
  n_= NULL;
}

monomial::monomial(int d, int size, uint64_t v) {
  d_= d;
  n_= new BigNum(size);
  n_->value_[0]= v;
}

monomial::~monomial() {
  d_= 0;
  if(n_!=NULL) {
    delete n_;
    n_= NULL;
  }
}

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
  int i;

  if(a.Degree()<=num_c_)
    return false;
  ZeroPoly(a);
  for(i=Degree(); i>=0; i--) {
    c_[i]->CopyTo(*a.c_[i]);
  }
  return true;
}

bool Polynomial::CopyFrom(Polynomial& a) {
  return a.CopyTo(*this);
}

void Polynomial::Print(bool small) {
  int i;

  for(i=(num_c_-1); i>0;i--) {
    if(small) {
      if(c_[i]->value_[0]!=0ULL) {
        printf("%lld x**%d +", c_[i]->value_[0], i);
    }
    } else {
    }
  }
  if(small) {
      printf("%lld (mod %lld)", c_[0]->value_[0], m_->value_[0]);
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

Polynomial* MakePoly(int size_num, int num_c, int n, monomial* m) {
  Polynomial* p= new Polynomial(size_num, num_c);
  if(p==NULL)
    return NULL;

  int i;
  for(i=0; i<n; i++) {
    p->c_[m[i].d_]->CopyFrom(*m[i].n_);
  }
  return p;
}

// caller ensures a, b and c are polynomials over the same field
bool PolyAdd(Polynomial& a, Polynomial& b, Polynomial& c) {
  if(max(a.Degree(), b.Degree())<=c.num_c_)
    return false;
  if(b.Degree()>a.Degree())
    return PolyAdd(b,a,c);
  int i;

  ZeroPoly(c);
  for(i=0;i<=b.Degree(); i++ ) {
    if(!BigModAdd(*a.c_[i], *b.c_[i], *a.m_, *c.c_[i]))
      return false;
  }
  for(;i<=a.Degree();i++) {
    if(!c.c_[i]->CopyFrom(*a.c_[i]))
      return false;
  }
  return true;
}

bool PolySub(Polynomial& a, Polynomial& b, Polynomial& c) {
  if(max(a.Degree(), b.Degree())<=c.num_c_)
    return false;

  int i;

  ZeroPoly(c);
  if(b.Degree()<=a.Degree()) {
    for(i=0;i<=b.Degree(); i++ ) {
      if(!BigModSub(*a.c_[i], *b.c_[i], *a.m_, *c.c_[i]))
        return false;
    }
    for(;i<=a.Degree(); i++ ) {
        if(!c.c_[i]->CopyFrom(*a.c_[i]))
          return false;
    }
  } else {
    for(i=0;i<=a.Degree(); i++ ) {
      if(!BigModSub(*a.c_[i], *b.c_[i], *a.m_, *c.c_[i]))
        return false;
    }
    for(;i<=b.Degree(); i++ ) {
      if(!BigModSub(Big_Zero, *b.c_[i], *a.m_, *c.c_[i]))
          return false;
    }
  }
  return true;
}

bool PolyMult(Polynomial& a, Polynomial& b, Polynomial& c) {
  if((a.Degree()+b.Degree())<=c.num_c_)
    return false;

  int     i, j, k;
  BigNum  t(2*a.m_->Size()+1);
  BigNum  r(2*a.m_->Size()+1);

  ZeroPoly(c);
  for(i=0; i<=a.Degree(); i++) {
    for(j=0; j<=b.Degree(); j++) {
      k= i+j;
      if(!BigModMult(*a.c_[i], *b.c_[j], *a.m_, t))
        return false;
      if(!BigModAdd(t, *c.c_[k], *a.m_, r))
        return false;
      r.CopyTo(*c.c_[k]);
    }
  }
  return true;
}

bool ZeroPoly(Polynomial& a) {
  int i;

  for(i=0; i<a.num_c_; i++)
    a.c_[i]->ZeroNum();
  return true;
}

bool OnePoly(Polynomial& a) {
  int i;

  for(i=0; i<a.num_c_; i++)
    a.c_[i]->ZeroNum();
  a.c_[i]->value_[0]= 1ULL;
  return true;
}

// a(x)= b(x)*q(x)+q(x)
// deg a(x)>=deg b(x)
bool PolyEuclid(Polynomial& a, Polynomial& b, Polynomial& q, Polynomial& r) {
  if(q.num_c_<=(a.Degree()+b.Degree()))
    return false;
  if(r.num_c_<=a.Degree())
    return false;
  Polynomial  t(a.size_num_, a.num_c_, *a.m_);
  Polynomial  s(a.size_num_, a.num_c_, *a.m_);

  t.CopyFrom(a);
  r.CopyFrom(a);
  int     deg_t= t.Degree();
  int     deg_b= b.Degree();
  int     cur_q;

  BigNum  leading_t(*t.c_[deg_t], a.size_num_);
  BigNum  leading_b_inv(b.size_num_);
  BigNum  tn(b.size_num_);

  if(!BigModInv(*b.c_[deg_b], *a.m_, leading_b_inv))
    return false;

  while(deg_t>=deg_b) {
    cur_q= deg_t-deg_b;
    if(!BigModMult(*t.c_[deg_t], leading_b_inv, *a.m_, tn))
      return false; 
    q.c_[cur_q]->CopyFrom(tn);
    MultiplyPolyByMonomial(b, deg_t-deg_b, tn, s);
    PolySub(t, s, r);
    t.CopyFrom(r);
    deg_t= t.Degree();
  }
  return true;
}

bool PolyExtendedGcd(Polynomial& a, Polynomial& b, Polynomial& x, Polynomial& y, 
                     Polynomial& g) {
  return false;
}

bool MultiplyPolyByMonomial(Polynomial& a, int d, BigNum& n, Polynomial& r) {
  int i;

  if(r.Degree()<=(a.Degree()+d))
    return false;
  ZeroPoly(r);
  for(i=a.Degree(); i>=0; i--) {
    if(!BigModMult(*a.c_[i], n, *a.m_, *r.c_[i+d]))
      return false;
  }
  return true;
}

