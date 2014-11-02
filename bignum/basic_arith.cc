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
// File: basic_arith.cc for bignums

#include "cryptotypes.h"
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "bignum.h"
#include "intel64_arith.h"

// returns  1, if l>r
// returns  0, if l==r
// returns -1, if l<r
int BigCompare(BigNum& l, BigNum& r) {
  if(l.IsPositive() && r.IsNegative())
    return 1;
  if(r.IsPositive() && r.IsNegative())
    return -1;
  if(l.IsPositive() && r.IsPositive())
    return DigitArrayCompare(l.Size(), l.ValuePtr(), r.Size(), r.ValuePtr());
  return 1-DigitArrayCompare(l.Size(), l.ValuePtr(), r.Size(), r.ValuePtr());
}

string* BigConvertToDecimal(BigNum& a) {
  int   k= 32*a.size_;
  char* str= new char[k];

  if(!DigitArrayConvertToDecimal(a.size_, a.value_, &k, str)) {
    if(str!=NULL) {
      // delete str;
      str= NULL;
    }
    return NULL;
  }
  string* s= new string(str);
  if(str!=NULL) {
    // delete str;
    str= NULL;
  }
  return s;
}

BigNum* BigConvertFromDecimal(const char* in) {
  int     k= strlen(in);
  int     m= ((k+29)/30)+6;
  BigNum* n= new BigNum(m);
  n->size_= DigitArrayConvertFromDecimal(in, n->capacity_, n->value_);
  return n;
}

string* BigConvertToHex(BigNum& a) {
  int   k= 18*a.size_;
  char* str= new char[k];

  if(!DigitArrayConvertToHex(a.size_, a.value_, &k, str)) {
    if(str!=NULL) {
      delete str;
      str= NULL;
    }
    return NULL;
  }
  string* s= new string(str);
  if(str!=NULL) {
    delete str;
    str= NULL;
  }
  return s;
}

BigNum* BigConvertFromHex(const char* in) {
  int     k= strlen(in);
  int     m= ((k+31)/16)*16+1;
  BigNum* n= new BigNum(m);

  n->size_= DigitArrayConvertFromHex(in, n->capacity_, n->value_);
  return n;
}

void  PrintNumToLog(BigNum& n, uint64_t base) {
  string*   s= NULL;

  if(base==10) {
    s= BigConvertToDecimal(n);
  } else if(base==16) {
    s= BigConvertToHex(n);
  } else {
    return;
  }
  LOG(INFO) << *s;
}

void  PrintNumToConsole(BigNum& n, uint64_t base) {
  string*   s= NULL;

  if(base==10) {
    s= BigConvertToDecimal(n);
  } else if(base==16) {
    s= BigConvertToHex(n);
  } else {
    return;
  }
  if(s==NULL)
    return;
  if(n.IsNegative())
    printf("(-%s)", s->c_str());
  else
    printf("(%s)", s->c_str());
  delete s;
  return;
}

int  BigHighDigit(BigNum& a) {
  a.Normalize();
  if(a.size_==1) {
    if(a.value_[0]!=0) 
      return 1;
    else
      return 0;
  }
  return a.size_;
}

int BigHighBit(BigNum& a) {
  return NBITSINUINT64*(a.size_-1)+HighBitInDigit(a.value_[a.size_-1]);
}

bool BigBitPositionOn(BigNum& a, int n) {
  int j= (n-1)/NBITSINUINT64;
  int k= n-j*NBITSINUINT64-1;

  if(a.size_<(j+1))
    return false;
  uint64_t  x= a.value_[j];
  if((x>>k)&1)
    return true;
  return false;
}

int BigMaxPowerOfTwoDividing(BigNum& a) {
  int       i, j;
  uint64_t  n= 0;
  uint64_t  x;
  bool      getout= false;

  for(i=0; i<a.size_; i++) {
    x= a.value_[i];
    for(j=0; j<NBITSINUINT64;j++) {
      if((x&1ULL)!=0) {
        getout= true;
        break;
      }
      n++;
      x>>= 1;
    }
    if(getout)
      break;
  }
  return n;
}

bool BigShift(BigNum& a, int64_t shift, BigNum& r)  {
  int   k;

  // positive shift increases value
  if(shift>0)  {
    k= DigitArrayShiftUp(a.size_, a.value_, (int)shift,
                      r.capacity_, r.value_);
    if(k<0)
      return false;
    r.size_= k;
    return true;
  } else if(shift==0LL) {
    return r.CopyFrom(a);
  } else {
    k= DigitArrayShiftDown(a.size_, a.value_, (int)-shift,
                      r.capacity_, r.value_);
    if(k<0)
      return false;
    r.size_= k;
    return true;
  }
}

bool BigUnsignedAdd(BigNum& a, BigNum& b, BigNum& r) {
  int k = DigitArrayAdd(a.size_, a.value_, b.size_, b.value_,
                    r.capacity_, r.value_);
  if(k<0)
    return false;
  r.size_= k;
  return true;
}

bool BigUnsignedSub(BigNum& a, BigNum& b, BigNum& r) {
  int k = DigitArraySub(a.size_, a.value_, b.size_, b.value_,
                    r.capacity_, r.value_);
  if(k<0)
    return false;
  r.size_= k;
  r.Normalize();
  return true;
}

bool BigUnsignedMult(BigNum& a, BigNum& b, BigNum& r) {
  int k = DigitArrayMult(a.size_, a.value_, b.size_, b.value_,
                    r.capacity_, r.value_);
  if(k<0) {
    return false;
  }
  r.size_= k;
  r.Normalize();
  return true;
}

bool BigUnsignedEuclid(BigNum& a, BigNum& b, BigNum& q, BigNum& r) {
  int   size_q= q.capacity_;
  int   size_r= r.capacity_;
  if(!DigitArrayDivisionAlgorithm(a.size_, a.value_, b.size_, b.value_,
                    &size_q, q.value_, &size_r, r.value_)) {
    LOG(ERROR) << "DigitArrayDivisionAlgorithm fails in BigUnsignedEuclid\n";
    return false;
  }
  q.size_= DigitArrayComputedSize(size_q, q.value_);
  r.size_= DigitArrayComputedSize(size_r, r.value_);
  if(r.size_>b.size_) {
    LOG(ERROR)<<"*** something's wrong in BigUnsignedEuclid\n";
#if 0
    printf("a: "); PrintNumToConsole(a, 10ULL); printf("\n");
    printf("b: "); PrintNumToConsole(b, 10ULL); printf("\n");
    printf("r: "); PrintNumToConsole(r, 10ULL); printf("\n");
    printf("q: "); PrintNumToConsole(q, 10ULL); printf("\n");
#endif
    r.ZeroNum();
    return false;
  }
  return true;
}

bool BigUnsignedDiv(BigNum& a, BigNum& b, BigNum& q) {
  BigNum  tmp(2*a.capacity_+1);
  return BigUnsignedEuclid(a, b, q, tmp);
}

bool BigUnsignedSquare(BigNum& a, BigNum& r) {
  int k = DigitArraySquare(a.size_, a.value_, 
                           r.capacity_, r.value_);
  if(k<0)
    return false;
  r.size_= k;
  return true;
}

bool BigUnsignedAddTo(BigNum& a, BigNum& b) {
  int k= DigitArrayAddTo(a.capacity_, a.size_, a.value_ , b.size_, b.value_);
  if(k<0)
    return false;
  a.size_= k;
  return true;
}

bool BigUnsignedSubFrom(BigNum& a, BigNum& b) {
  int k= DigitArraySubFrom(a.capacity_, a.size_, a.value_ , b.size_, b.value_);
  if(k<0)
    return false;
  a.size_= k;
  return true;
}

bool BigUnsignedInc(BigNum& a) {
  uint64_t  one= 1ULL;
  int       k= DigitArrayAddTo(a.size_, a.size_, a.value_, 1, &one);
  if(k<0)
    return false;
  return true;
}

bool BigUnsignedDec(BigNum& a) {
  uint64_t  one= 1ULL;
  int       k= DigitArraySubFrom(a.size_, a.size_, a.value_, 1, &one);
  if(k<0)
    return false;
  return true;
}

bool BigAdd(BigNum& a, BigNum& b, BigNum& r) {
  if(a.IsPositive() && b.IsPositive()) {
    if(!BigUnsignedAdd(a, b, r))
      return false;
    r.sign_= false;
    r.Normalize();
    return true;
  }
  else if(a.IsNegative() && b.IsNegative()) {
    if(!BigUnsignedAdd(a, b, r))
      return false;
    r.sign_= true;
    r.Normalize();
    return true;
  }
  else if(a.IsPositive() && b.IsNegative()) {
    int cmp=  DigitArrayCompare(a.size_, a.value_, b.size_, b.value_);
    if(cmp>0) {
      r.sign_= false;
      return BigUnsignedSub(a, b, r);
    }
    if(cmp==0) {
      r.ZeroNum();
      return true;
    }
    r.sign_= true;
    return BigUnsignedSub(b, a, r);
  }
  else {    // a<0, b>0
    int cmp=  DigitArrayCompare(b.size_, b.value_, a.size_, a.value_);
    if(cmp>0) {
      r.sign_= false;
      return BigUnsignedSub(b, a, r);
    }
    if(cmp==0) {
      r.ZeroNum();
      return true;
    }
    r.sign_= true;
    return BigUnsignedSub(a, b, r);
  }
}

bool BigSub(BigNum& a, BigNum& b, BigNum& r) {
  if(a.IsPositive() && b.IsNegative()) {
    if(!BigUnsignedAdd(a, b, r))
      return false;
    r.sign_= false;
    return true;
  }
  else if(a.IsNegative() && b.IsPositive()) {
    if(!BigUnsignedAdd(a, b, r))
      return false;
    r.sign_= true;
    return true;
  }
  else if(a.IsPositive() && b.IsPositive()) {
    int cmp=  DigitArrayCompare(a.size_, a.value_, b.size_, b.value_);
    if(cmp>0) {
      r.sign_= false;
      return BigUnsignedSub(a, b, r);
    }
    if(cmp==0) {
      r.ZeroNum();
      return true;
    }
    r.sign_= true;
    return BigUnsignedSub(b, a, r);
  }
  else {    // a<0, b<0
    int cmp=  DigitArrayCompare(b.size_, b.value_, a.size_, a.value_);
    if(cmp>0) {
      r.sign_= true;
      return BigUnsignedSub(b, a, r);
    }
    if(cmp==0) {
      r.ZeroNum();
      return true;
    }
    r.sign_= false;
    return BigUnsignedSub(a, b, r);
  }
}

bool BigMult(BigNum& a, BigNum& b, BigNum& r) {
  if(a.IsPositive() != b.IsPositive())
    r.sign_= true;
  return BigUnsignedMult(a,b,r);
}

bool BigDiv(BigNum& a, BigNum& b, BigNum& r) {
  if(a.IsPositive() != b.IsPositive())
    r.sign_= true;
  return BigUnsignedDiv(a,b,r);
}

bool BigSquare(BigNum& a, BigNum& r) {
  return BigUnsignedSquare(a, r);
}

