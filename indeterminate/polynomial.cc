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
  n_= nullptr;
}

monomial::monomial(int d, int size, uint64_t v) {
  d_= d;
  n_= new BigNum(size);
  n_->value_[0]= v;
}

monomial::~monomial() {
  d_= 0;
  if(n_!=nullptr) {
    delete n_;
    n_= nullptr;
  }
}

Polynomial::Polynomial(int size_num, int num_c) {
  int i;

  m_= new BigNum(size_num);

  c_= new BigNum* [num_c];
  for(i= 0; i<num_c; i++)
    c_[i]= new BigNum(size_num);
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
    if(c_[i]!=nullptr)
      delete c_[i];
    c_[i]= nullptr;
  }
  if(m_!=nullptr)
    delete m_;
  m_= nullptr;
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

  if(a.num_c_<=Degree())
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
        printf("%lld x**%d + ", c_[i]->value_[0], i);
      }
    } else {
      if(!c_[i]->IsZero()) {
        PrintNumToConsole(*c_[i], 10ULL);
        printf(" x**%d +\n", i);
      }
    }
  }
  if(small) {
      printf("%lld (mod %lld)", c_[0]->value_[0], m_->value_[0]);
  } else {
      PrintNumToConsole(*c_[0], 10ULL); 
      printf(" (mod ");
      PrintNumToConsole(*m_, 10ULL); printf(" )\n");
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
  if(p==nullptr)
    return nullptr;

  int i;
  for(i=0; i<n; i++) {
    p->c_[m[i].d_]->CopyFrom(*m[i].n_);
  }
  return p;
}

// caller ensures a, b and c are polynomials over the same field
bool PolyAdd(Polynomial& a, Polynomial& b, Polynomial& c) {
  if(max(a.Degree(), b.Degree())>=c.num_c_) {
    return false;
  }
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
  if(max(a.Degree(), b.Degree())>=c.num_c_)
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
  if((a.Degree()+b.Degree())>=c.num_c_) 
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
  a.c_[0]->value_[0]= 1ULL;
  return true;
}

// a(x)= b(x)*q(x)+q(x)
// deg a(x)>=deg b(x)
bool PolyEuclid(Polynomial& a, Polynomial& b, Polynomial& q, Polynomial& r) {
  if(q.num_c_<=(a.Degree()-b.Degree()))
    return false;
  if(r.num_c_<=b.Degree())
    return false;
  Polynomial  t(a.size_num_, a.num_c_, *a.m_);
  Polynomial  s(a.size_num_, a.num_c_, *a.m_);

  if(!t.CopyFrom(a))
    return false;
  int     deg_t= t.Degree();
  int     deg_b= b.Degree();
  int     cur_q;
  if(deg_t<deg_b) {
    if(!r.CopyFrom(a))
      return true;
  }

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
  Polynomial*   a_coeff[3]= {nullptr, nullptr, nullptr};
  Polynomial*   b_coeff[3]= {nullptr, nullptr, nullptr};
  Polynomial*   c[3]= {nullptr, nullptr, nullptr};

  int           n= a.num_c_+b.num_c_+2;
  Polynomial    q(a.size_num_, n, *a.m_);
  Polynomial    r(a.size_num_, n, *a.m_);
  Polynomial    t1(a.size_num_, n, *a.m_);
  Polynomial    t2(a.size_num_, n, *a.m_);
  int           old= 0;
  int           current= 1;
  int           next= 2;
  bool          ret= true;
  int           i;

  for(i=0; i<3; i++) {
    a_coeff[i]= new Polynomial(a.size_num_, n, *a.m_);
    b_coeff[i]= new Polynomial(a.size_num_, n, *a.m_);
    c[i]= new Polynomial(a.size_num_, n, *a.m_);
  }

  OnePoly(*a_coeff[0]);
  ZeroPoly(*b_coeff[0]);
  ZeroPoly(*a_coeff[1]);
  OnePoly(*b_coeff[1]);
  a.CopyTo(*c[0]);
  b.CopyTo(*c[1]);

  for(;;) {
    ZeroPoly(r);
    ZeroPoly(q);
    ZeroPoly(t1);
    ZeroPoly(t2);

    // c[new]= q*c[old] +r;
    ret= PolyEuclid(*c[old], *c[current], q, r);
    if(!ret) {
      goto done;
    }
    if(r.IsZero())
      break;
    r.CopyTo(*c[next]);
    PolyMult(q, *a_coeff[current], t1);
    PolyMult(q, *b_coeff[current], t2);
    PolySub(*a_coeff[old], t1, *a_coeff[next]);
    PolySub(*b_coeff[old], t2, *b_coeff[next]);
    old= (old+1)%3;
    current= (current+1)%3;
    next= (next+1)%3;
  }
 a_coeff[current]->CopyTo(x);
 b_coeff[current]->CopyTo(y);
 c[current]->CopyTo(g);

done:
  for(i=0;i<3; i++) {
    if(a_coeff[i]!=nullptr)
      delete a_coeff[i];
    a_coeff[i]= nullptr;
    if(b_coeff[i]!=nullptr)
      delete b_coeff[i];
    b_coeff[i]= nullptr;
    if(c[i]!=nullptr)
      delete c[i];
    c[i]= nullptr;
  }
  return ret;
}

bool MultiplyPolyByMonomial(Polynomial& a, int d, BigNum& n, Polynomial& r) {
  int i;

  if(r.num_c_<=(a.Degree()+d))
    return false;
  ZeroPoly(r);
  for(i=a.Degree(); i>=0; i--) {
    if(!BigModMult(*a.c_[i], n, *a.m_, *r.c_[i+d]))
      return false;
  }
  return true;
}

bool ReduceModPoly(Polynomial& a, Polynomial& m, Polynomial& r) {
  Polynomial  t(a.size_num_, a.num_c_, *a.m_);
  return PolyEuclid(a, m, t, r);
}

