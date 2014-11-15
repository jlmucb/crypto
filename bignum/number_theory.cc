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
// File: number_theory.cc

#include "cryptotypes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "bignum.h"
#include "intel64_arith.h"

bool BigExtendedGCD(BigNum& a, BigNum& b, BigNum& x, BigNum& y, BigNum& g) {
  BigNum* a_coeff[3]= {NULL, NULL, NULL};
  BigNum* b_coeff[3]= {NULL, NULL, NULL};
  BigNum* c[3]= {NULL, NULL, NULL};

  int     n= a.size_>b.size_?a.size_:b.size_;
  BigNum  q(2*n+1);
  BigNum  r(2*n+1);
  BigNum  t1(2*n+1);
  BigNum  t2(2*n+1);
  int     old= 0;
  int     current= 1;
  int     next= 2;
  bool    ret= true;
  int     i;

  for(i=0;i<3; i++) {
    a_coeff[i]= new BigNum(2*n+1);
    b_coeff[i]= new BigNum(2*n+1);
    c[i]= new BigNum(2*n+1);
  }

  a_coeff[0]->CopyFrom(Big_One);
  b_coeff[0]->CopyFrom(Big_Zero);
  a_coeff[1]->CopyFrom(Big_Zero);
  b_coeff[1]->CopyFrom(Big_One);
  a.CopyTo(*c[0]);
  b.CopyTo(*c[1]);

  for(;;) {
    r.ZeroNum();
    q.ZeroNum();
    t1.ZeroNum();
    t2.ZeroNum();

    // c[new]= q*c[old] +r;
    ret= BigUnsignedEuclid(*c[old], *c[current], q, r);
    if(!ret)
      goto done;
    if(r.IsZero())
      break;
    r.CopyTo(*c[next]);
    BigMult(q, *a_coeff[current], t1);
    BigMult(q, *b_coeff[current], t2);
    BigSub(*a_coeff[old], t1, *a_coeff[next]);
    BigSub(*b_coeff[old], t2, *b_coeff[next]);
    old= (old+1)%3;
    current= (current+1)%3;
    next= (next+1)%3;
  }

 a_coeff[current]->CopyTo(x);
 b_coeff[current]->CopyTo(y);
 c[current]->CopyTo(g);

done:
  for(i=0;i<3; i++) {
    if(a_coeff[i]!=NULL)
      delete a_coeff[i];
    a_coeff[i]= NULL;
    if(b_coeff[i]!=NULL)
      delete b_coeff[i];
    b_coeff[i]= NULL;
    if(c[i]!=NULL)
      delete c[i];
    c[i]= NULL;
  }
  return ret;
}

bool BigCRT(BigNum& s1, BigNum& s2, BigNum& m1, BigNum& m2, BigNum& r) {
  int     m= m1.size_>m2.size_?m1.size_:m2.size_;
  if(s1.size_>m)
    m= s1.size_;
  if(s2.size_>m)
    m= s2.size_;
  BigNum  u1(3*m+1);
  BigNum  u2(3*m+1);
  BigNum  t1(3*m+1);
  BigNum  t2(3*m+1);
  BigNum  r1(3*m+1);
  BigNum  r2(3*m+1);
  BigNum  n(3*m+1);

  // u1 m1 + u2 m2= 1
  if(!BigExtendedGCD(m1, m2, u1, u2, t1))
    return false;

  // r= u1 m1 s2 + u2 m2 s1
  if(!BigMult(u1, m1, t1))
    return false;
  if(!BigMult(t1, s2, r1))
    return false;
  if(!BigMult(u2, m2, t2))
    return false;
  if(!BigMult(t2, s1, r2))
    return false;
  if(!BigMult(m1, m2, n))
    return false;
  if(!BigAdd(r1, r2, r))
    return false;
  if(!BigModNormalize(r, n))
    return false;
  return true;
}

bool BigMod(BigNum& a, BigNum& m, BigNum& r) {
  if(!r.CopyFrom(a))
    return false;
  if(!BigModNormalize(r,m))
    return false;
  return true;
}


bool BigModNormalize(BigNum& a, BigNum& m) {
  if(!a.sign_ && BigCompare(a, m)<0)
    return true;

  int     n= a.size_>m.size_?a.size_:m.size_;
  BigNum  t1(1+2*n);
  BigNum  t2(1+2*n);

  if(a.sign_) {
    if(!BigUnsignedEuclid(a, m, t1, t2)) 
      return false;
    if(!BigUnsignedAddTo(t1, Big_One))
      return false;
    t2.ZeroNum();
    if(!BigUnsignedMult(t1, m, t2))
      return false;
    t1.ZeroNum();
    if(!BigAdd(a, t2, t1))
      return false;
    t1.CopyTo(a);
  }
  if(a.sign_) 
      return false;

  if(BigCompare(a, m)>=0) {
    if(!BigUnsignedEuclid(a, m, t1, t2))
      return false;
    t2.Normalize();
    a.CopyFrom(t2);
    a.Normalize();
  }
  return true;
}

bool BigModAdd(BigNum& a, BigNum& b, BigNum& m, BigNum& r) {
  bool    ret= true;

  if(!BigModNormalize(a,m)) {
    ret= false;
    goto done;
  }
  if(!BigModNormalize(b,m)) {
    ret= false;
    goto done;
  }
  ret= BigUnsignedAdd(a, b, r);
  if(!ret)
    goto done;
  if(!BigModNormalize(r, m)) {
    ret= false;
    goto done;
  }

done:
  return ret;
}

bool BigModSub(BigNum& a, BigNum& b, BigNum& m, BigNum& r) {
  bool    ret= true;

  if(!BigModNormalize(a,m)) {
    ret= false;
    goto done;
  }
  if(!BigModNormalize(b,m)) {
    ret= false;
    goto done;
  }

  ret= BigSub(a, b, r);
  if(!ret)
    goto done;
  ret= BigModNormalize(r, m);

done:
  return ret;
}

bool checkBigModMult(BigNum& ab, BigNum& m, BigNum& r) {
  BigNum  q(4*m.capacity_+2);
  BigNum  nr(4*m.capacity_+2);
  BigNum  ru(4*m.capacity_+2);
  bool    ret= true;

  if(!BigUnsignedEuclid(ab, m, q, nr)) {
    printf("checkBigModMult, BigUnsignedEuclid failed\n");
    return false;
  }
  if(!BigUnsignedMult(m, q, ru)) {
    printf("checkBigModMult, BigUnsignedMult failed\n");
    return false;
  }
  if(!BigUnsignedAdd(ru, r, nr)) {
    printf("checkBigModMult, BigUnsignedAddfailed\n");
    return false;
  }
  if(BigCompare(ab, nr)!=0) {
    printf("checkBigModMult failed\n");
    printf("ab: "); PrintNumToConsole(ab, 16ULL); printf("\n");
    printf("nr: "); PrintNumToConsole(nr, 16ULL); printf("\n");
    ret= false;
  }
  return ret;
}

bool BigModMult(BigNum& a, BigNum& b, BigNum& m, BigNum& r) {
  int   n= a.size_>b.size_?a.size_:b.size_;

  if(m.size_>n)
    n= m.size_;
  if(!BigModNormalize(a, m))
    return false;
  if(!BigModNormalize(b, m))
    return false;
  BigNum  t(2*n+2);
  if(!BigUnsignedMult(a, b, t))
    return false;
  return BigMod(t, m, r);
}

bool BigModSquare(BigNum& a, BigNum& m, BigNum& r) {
  return BigModMult(a, a, m, r);
}

bool BigModInv(BigNum& a, BigNum& m, BigNum& r) {
  BigNum  x(2*m.capacity_+1);
  BigNum  y(2*m.capacity_+1);
  BigNum  g(2*m.capacity_+1);

  if(!BigModNormalize(a,m))
    return false;
  if(!BigExtendedGCD(a, m, x, y, g))
    return false;
  r.CopyFrom(x);
  return BigModNormalize(r, m);

}

// r= a/b
bool BigModDiv(BigNum& a, BigNum& b, BigNum& m, BigNum& r) {
  int     n= a.size_>b.size_?a.size_:b.size_;
  if(m.size_>n)
    n= m.size_;
  BigNum  x(3*n+1);

  if(!BigModInv(b, m, x))
    return false;
  if(!BigModMult(a, x, m, r))
    return false;
  return BigModNormalize(r, m);
}

bool BigModExp(BigNum& b, BigNum& e, BigNum& m, BigNum& r) {
  BigNum* accum[2]= {NULL, NULL};
  BigNum* doubled[2]= {NULL, NULL};
  int     accum_current= 0;
  int     accum_next= 1;
  int     doubler_current= 0;
  int     doubler_next= 1;
  bool    ret= true;
  int     i;
  int     k;

  if(!BigModNormalize(b,m))
    return false;

  k= BigHighBit(e);
  if(k==0) {
    Big_One.CopyTo(r);
    goto done;
  }
  for(i=0;i<2; i++) {
    accum[i]= new BigNum(4*m.size_+1);
    doubled[i]= new BigNum(4*m.size_+1);
  }
  accum[accum_current]->CopyFrom(Big_One);
  doubled[doubler_current]->CopyFrom(b);
  for(i=1; i<k;i++) {
    if(BigBitPositionOn(e, i)) {
      accum[accum_next]->ZeroNum();
      if(!BigModMult(*accum[accum_current], *doubled[doubler_current], 
                  m, *accum[accum_next])) {
        LOG(ERROR)<<"BigModMult 1 failed in BigModExp\n";
        ret= false;
        goto done;
      }
      accum_current= (accum_current+1)%2;
      accum_next= (accum_next+1)%2;
    }
    doubled[doubler_next]->ZeroNum();
    if(!BigModSquare(*doubled[doubler_current], m, *doubled[doubler_next])) {
        LOG(ERROR)<<"BigModSquare failed in BigModExp\n";
        ret= false;
        goto done;
    }
    doubler_current= (doubler_current+1)%2;
    doubler_next= (doubler_next+1)%2;
  }
  if(BigBitPositionOn(e, i)) {
    accum[accum_next]->ZeroNum();
    BigModMult(*accum[accum_current], *doubled[doubler_current], 
                m, *accum[accum_next]);
    accum_current= (accum_current+1)%2;
    accum_next= (accum_next+1)%2;
  }
  if(ret) {
    r.CopyFrom(*accum[accum_current]);
    ret= BigModNormalize(r, m);
#if 0
    checkBigModMult(*accum[accum_current], m, r);
#endif
  }

done:
  for(i=0;i<2; i++) {
    if(accum[i]!=NULL) {
      delete accum[i];
    }  
    if(doubled[i]!=NULL) {
      delete doubled[i];
    }  
  }
  return ret;
}

#define MAXPRIMETRYS 25000

bool BigGenPrime(BigNum& p, uint64_t num_bits) {
  int i, j;

  for(i=0; i<MAXPRIMETRYS; i++) {
    p.ZeroNum();
    if(!GetCryptoRand(num_bits, (byte*)p.value_)) {
      LOG(ERROR)<<"GetCryptoRand in BigGenPrime fails\n";
      return false;
    }
    p.value_[p.size_-1]|= (1ULL)<<63;
    p.value_[0]|= 1ULL;
    p.Normalize();
    for(j=0; j<250;j++, i++) {

      if(BigIsPrime(p)) {
#if 1
        printf("BigGenPrime %d bits, %d tries\n", (int)num_bits, i+1);
#endif
        return true;
      }
      if(!BigUnsignedAddTo(p, Big_Two)) {
        LOG(ERROR) << "BigUnsignedAddTo failed in BigGenPrime\n";
        return false;
      }
    }
  }
#if 1
  printf("BigGenPrime %d bits, failed in %d tries\n", (int)num_bits, i+1);
#endif
  return false;
}

bool    rands_avail= false;
BigNum* random_nums[40];

bool FillRandom(int n, BigNum** random_array) {

  int i;

  if(n>20)
    return false;

  if(!rands_avail) {
    random_nums[0]= new BigNum(5, 2ULL);
    for(i=0; i<19;i++) {
      random_nums[i+1]= new BigNum(5, 2ULL+(uint64_t)(19*i));
      random_nums[i+1]->Normalize();
    }
    rands_avail= true;
  }
  for(i=0;i<20; i++) {
    random_array[i]= random_nums[i];
  }

  return true;
}

/*
 *  n-1= 2^sr, r odd
 *  for(i=0; i<trys, i++) {
 *    choose a random: 2<= a <=n-2
 *    compute y= a^r (mod n)
 *    if( y!= 1 && y!=n-1) {
 *      j=1
 *      while (j < s and y!= n-1) {
 *        y=y^2 (mod n)
 *        if(y==1) return false;
 *        j++
 *      }
 *      if (y!=n-1) return false;
 *    }
 *    return true;
 *        
 *  }
 */
bool BigMillerRabin(BigNum& n, BigNum** random_a, int trys) {
  BigNum  n_minus_1(2*n.size_);
  BigNum  odd_part_n_minus_1(2*n.size_);
  BigNum  y(4*n.size_+1);
  BigNum  z(4*n.size_+1);
  int     i;
  int     j;
  int     shift;

#if 0
  printf("BigMillerRabin: "); PrintNumToConsole(n, 10ULL); printf("\n");
#endif
  if(!BigSub(n, Big_One, n_minus_1))
    return false;
  shift= BigMaxPowerOfTwoDividing(n_minus_1);
  if(shift>0) {
    if(!BigShift(n_minus_1, -shift, odd_part_n_minus_1))
      return false;
  }
  for(i=0; i<trys; i++) {
    y.ZeroNum();
    if(!BigModExp(*random_a[i], odd_part_n_minus_1, n, y))
      return false;
    if(BigCompare(y, Big_One)==0 || BigCompare(y, n_minus_1)==0)
      continue;
    for(j=0; j<shift; j++) {
        z.ZeroNum();
        if(!BigModMult(y, y, n, z))
          return false;
        if(BigCompare(z, Big_One)==0)
          return false;
        }
        y.CopyFrom(z);
        if(BigCompare(y, n_minus_1)==0)
          break;
    }
    if(BigCompare(y, n_minus_1)!=0)
      return false;
  return true;
}

bool BigIsPrime(BigNum& n) {
  extern  uint64_t smallest_primes[];
  extern  int      num_smallest_primes;
  int              i;
  bool             ret= true;
  int              k;
  int              m;
  uint64_t*        q= new uint64_t [n.size_];
  uint64_t         r;
  BigNum**         random_a= new BigNum*[20];

  for(i=0; i<num_smallest_primes;i++) {
    if(n.size_==1 && smallest_primes[i]>=n.value_[0])
      return true;
    k= n.size_;
    m= DigitArrayShortDivisionAlgorithm(n.size_, n.value_, 
           (uint64_t)smallest_primes[i], &k, q, &r);
    if(m<0) {
      LOG(ERROR) << "DigitArrayShortDivisionAlgorithm failed in BigIsPrime\n";
      ret= false;
      goto done;
    }
    if(r==0ULL)
      return false;
  }
  if(!ret)
    goto done;
  if(!FillRandom(20, random_a)) {
    LOG(ERROR) << "Couldnt FillRandom in BigIsPrime\n";
    return false;
  }
  ret= BigMillerRabin(n, random_a);

done:
  if(q!=NULL)
    delete q;
  return ret;
}

bool BigModIsSquare(BigNum& n, BigNum& p) {
  BigNum    p_minus_1(n.size_);
  BigNum    e(n.size_);
  BigNum    residue(4*p.capacity_+1);
  uint64_t  unused;
  int       size_e;

  BigSub(p, Big_One, p_minus_1);
  size_e= DigitArrayComputedSize(p_minus_1.size_, p_minus_1.value_);
  int       k= DigitArrayShortDivisionAlgorithm(p_minus_1.size_, p_minus_1.value_, 
                        2ULL, &size_e, e.value_, &unused);
  e.size_= size_e;
  if(k<0) {
    LOG(ERROR) << "DigitArrayShortDivisionAlgorithm failed in BigModIsSquare\n";
    return false;
  }
  e.size_= DigitArrayComputedSize(e.size_, e.value_);
  if(!BigModExp(n, e, p, residue)) {
    LOG(ERROR) << "BigModExp failed in BigModIsSquare\n";
    return false;
  }
  if(!residue.IsOne())
    return false;
  return true;
}

/*
 *  a>0, p!=2
 *  Find x: x^2=a (mod p).  Caller should have checked that a is a QR
 *    Reference: Cohen, A Course of computational number theory, p32.
 *  p-1= 2^e q 
 *  Pick a quadratic non-residue n
 *  z= n^q  (z is a generator)
 *  y= z; r= e; x= a^((q-1)/2) (mod p), b= ax^2
 *  x= ax  (RHS is a^2x^2= ab (mod p))
 *  while(b!=1) {
 *    -- at this point ab= x^2, y^(2^(r-1))= -1 (mod p), b^(2^(r-1)) =1 
 *    find smallest m: b^(2^m)= 1 (mod p) --- note m<r
 *    t=y^(2^(r-m-1)) (mod p)
 *    y= t^2
 *    r= m; x=xt; b=by;
 */
    // find smallest m: b^(2^m)= 1 (mod p) --- note m<r
int smallestunitaryexponent(BigNum& b, BigNum& p, int maxm) {
  BigNum    e(2*p.capacity_+1);
  BigNum    t(2*p.capacity_+1);
  int       i;

  for(i=1; i<maxm; i++) {
    if(!BigShift(Big_One, i, e))
      return -1;
    if(!BigModExp(b, e, p, t))
      return -1;
    if(BigCompare(Big_One, t)==0) {
      break;
    }
    e.ZeroNum();
    t.ZeroNum();
  }

  return i;
}

bool BigModTonelliShanks(BigNum& a, BigNum& p, BigNum& s) {
  BigNum    t1(2*p.size_+1);
  BigNum    t2(2*p.size_+1);

  BigNum    q(2*p.size_+1);       // p-1= 2^max_two_power q
  BigNum    p_minus(2*p.size_+1);

  int       max_two_power;
  int       m;

  BigNum    e(2*p.size_+1);       // exponent
  BigNum    n(2*p.size_+1);       // non-residue
  BigNum    x(2*p.size_+1);
  BigNum    y(2*p.size_+1);
  BigNum    z(2*p.size_+1);
  BigNum    b(2*p.size_+1);
  BigNum    t(2*p.size_+1);

  if(!BigUnsignedSub(p, Big_One, p_minus)) {
    LOG(ERROR) << "BigUnsignedSub 1 in BigModTonelliShanks failed\n";
    return false;
  }
  max_two_power= BigMaxPowerOfTwoDividing(p_minus);
  if(!BigShift(p_minus, -max_two_power, q)) {
    LOG(ERROR) << "BigShift 1 in BigModTonelliShanks failed\n";
    return false;
  }
  n.value_[0]= 2ULL;
  while(!BigModIsSquare(n, p)) {
    if(!BigUnsignedAddTo(n, Big_One)) {
      LOG(ERROR) << "BigUnsignedAddTo in BigModTonelliShanks failed\n";
      return false;
    }
  }
  if(!BigModExp(n, q, p, z)) {
    LOG(ERROR) << "BigModExp 1 in BigModTonelliShanks failed\n";
    return false;
  }
  if(!z.CopyTo(y)) {
    return false;
  }
  if(!BigUnsignedSub(q, Big_One, t1)) {
    LOG(ERROR) << "BigUnsignedSub 2 in BigModTonelliShanks failed\n";
    return false;
  }
  if(!BigShift(t1, -1, t2)) {
    LOG(ERROR) << "BigShift 2 in BigModTonelliShanks failed\n";
    return false;
  }
  if(!BigModExp(a, t2, p, x)) {
    LOG(ERROR) << "BigModExp 1 in BigModTonelliShanks failed\n";
    return false;
  }
  t1.ZeroNum();
  t2.ZeroNum();
  if(!BigModMult(x, x, p, t1)) {
    LOG(ERROR) << "BigModMult 1 in BigModTonelliShanks failed\n";
    return false;
  }
  if(!BigModMult(t1, a, p, b)) {
    LOG(ERROR) << "BigModMult 2 in BigModTonelliShanks failed\n";
    return false;
  }
  t1.ZeroNum();
  if(!BigModMult(x, a, p, t1)) {
    LOG(ERROR) << "BigModMult 3 in BigModTonelliShanks failed\n";
    return false;
  }
  t1.CopyTo(x);

  for(;;) {
    if(BigCompare(Big_One, b)==0)
      break;
    // at this point ab= x^2, y^(2^(r-1))= -1 (mod p), b^(2^(r-1)) =1 

    // find smallest m: b^(2^m)= 1 (mod p) --- note m<r
    m= smallestunitaryexponent(b, p, max_two_power);

    // t=y^(2^(r-m-1)) (mod p)
    if(!BigShift(Big_One, max_two_power-m-1, e)) {
      LOG(ERROR) << "BigShift 3 in BigModTonelliShanks failed\n";
      return false;
    }
    if(!BigModExp(y, t2, p, t)) {
      LOG(ERROR) << "BigModMult 3 in BigModTonelliShanks failed\n";
      return false;
    }
    y.ZeroNum();
  
    // y= t^2
    if(!BigModMult(t, t, p, y)) {
      return false;
    }
    // r= m; x=xt; b=by;
    max_two_power= m;
    t1.ZeroNum();
    if(!BigModMult(x, t, p, t1)) {
      LOG(ERROR) << "BigModMult 4 in BigModTonelliShanks failed\n";
      return false;
    }
    t1.CopyTo(x);
    t1.ZeroNum();
    if(!BigModMult(y, b, p, t1)) {
      LOG(ERROR) << "BigModMult 5 in BigModTonelliShanks failed\n";
      return false;
    }
    t1.CopyTo(y);
  }
  return true;
}

/*
 *  a>0, p!=2
 *  Find x: x^2=n (mod p)
 *  if(p==3 (mod 4)) x= a^((p+1)/4 (mod p)
 *  if(p==5 (mod 8)) put b= n^((p-1)/4) (mod p)
 *    if(b==1) x= a^((p+3)/8) (mod p)
 *    otherwise, x= (2a)(4a)^((p-5)/8)
 *  in all other cases, apply Tonneli-Shanks
 */
bool BigModSquareRoot(BigNum& n, BigNum& p, BigNum& r) {
  uint64_t  bot= p.value_[0]&0x7;
  BigNum    p_temp(p.size_);

  if(bot==1)
      return BigModTonelliShanks(n, p, r);
  
  BigNum  t1(1+2*p.size_);
  BigNum  t2(1+2*p.size_);
  BigNum  t3(1+2*p.size_);
  if(bot==3 || bot==7) {
    if(!BigUnsignedAdd(p, Big_One, p_temp)) {
      LOG(ERROR) << "BigUnsignedAdd 1 in BigModSquareRoot failed\n";
      return false;
    }
    if(!BigShift(p_temp, -2, t1)) {
      LOG(ERROR) << "BigShift 1 in BigModSquareRoot failed\n";
      return false;
    }
    if(!BigModExp(n, t1, p, r)) {
      LOG(ERROR) << "BigModExp 1 in BigModSquareRoot failed\n";
      return false;
    }
  } else if(bot==5) {

    if(!BigUnsignedSub(p, Big_One, p_temp)) {
      LOG(ERROR) << "BigUnsignedSub 2 in BigModSquareRoot failed\n";
      return false;
    }
    if(!BigShift(p_temp, -2, t1)) {
      LOG(ERROR) << "BigShift 2 in BigModSquareRoot failed\n";
      return false;
    }
    if(!BigModExp(n, t1, p, t2)) {
      LOG(ERROR) << "BigModExp 2 in BigModSquareRoot failed\n";
      return false;
    }

    if(BigCompare(Big_One, t2)==0) {
      p_temp.ZeroNum();
      // if(b==1) x= a^((p+3)/8) (mod p)
      p_temp.ZeroNum();
      t1.ZeroNum();
      if(!BigUnsignedAdd(p, Big_Three, p_temp)) {
        LOG(ERROR) << "BigUnsignedAdd 2 in BigModSquareRoot failed\n";
        return false;
      }
      if(!BigShift(p_temp, -3, t1)) {
        LOG(ERROR) << "BigShift 3 in BigModSquareRoot failed\n";
        return false;
      }
      if(!BigModExp(n, t1, p, r)) {
        LOG(ERROR) << "BigModExp 3 in BigModSquareRoot failed\n";
        return false;
      }
    } else {
      t1.ZeroNum();
      t2.ZeroNum();
      t3.ZeroNum();
      p_temp.ZeroNum();
      //  otherwise, x= (2a)(4a)^((p-5)/8)
      if(!BigUnsignedSub(p, Big_Five, p_temp)) {
        LOG(ERROR) << "BigUnsignedSub 3 in BigModSquareRoot failed\n";
        return false;
      }
      if(!BigShift(p_temp, -3, t1)) {
        LOG(ERROR) << "BigShift 4 in BigModSquareRoot failed\n";
        return false;
      }
      if(!BigShift(n, 2, t2)) {
        LOG(ERROR) << "BigShift 5 in BigModSquareRoot failed\n";
        return false;
      }
      if(!BigModExp(t2, t1, p, t3)) {
        return false;
      }
      t1.ZeroNum();
      t2.ZeroNum();
      if(!BigShift(n, 1, t2)) {
        LOG(ERROR) << "BigShift 6 in BigModSquareRoot failed\n";
        return false;
      }
      if(!BigModMult(t2, t3, p, r)) {
        LOG(ERROR) << "BigModMult in BigModSquareRoot failed\n";
        return false;
      }
    }
  } else {
      return false;
  }
  return true;
}

/*
 *  R>p, (p,R)=1.  Usually, R=2^r
 *  0<= T < pR, p'= -p^(-1) (mod R)
 *
 *  Reduction: (p, R)= 1.  U= Tp' (mod R)
 *    (T+Um)/R = TR^(-1) (mod p)
 *  Theorem: (T+Um)/R = TR^(-1) or TR^(-1) + p
 *
 *  Reduce
 *    A= T
 *    for(i=0;i<n; i++) {
 *      u[i]= a[i]p' mod b  (b is base, R=b^n)
 *      A= A+u[i]m b^i
 *    }
 *    A= A/b^i
 *    if(A>=p) A=- p;
 *    return A
 *
 *  Multiply.  0<= x, y <p.  R=b^n.  output: xyR^(-1) (mod p)
 *    A= 0
 *    for(i=0;i<n; i++) {
 *      u[i]= (a[0]+x[i]y[0]) p' mod b  (b is base, R=b^n)
 *      A= A+u[i]y[0] (mod b)
 *      A= (A+x[i]y+u[i]m)/b
 *    }
 *    if(A>=p)  A-= p
 *    return A
 */

// BigMakeMont(a,m,r)= a R (mod m)
bool BigMakeMont(BigNum& a, int r, BigNum& m, BigNum& mont_a) {
  int     n= a.size_>m.size_?a.size_:m.size_;
  int     k= (r+NBITSINUINT64-1)/NBITSINUINT64;
  if(k>n)
    n= k;

  BigNum  t1(1+2*n);

  if(m.IsZero()) {
    LOG(ERROR) << "Modulus is 0 BigMakeMont\n";
    return false;
  }
  if(!BigShift(Big_One, r, t1)) {
    LOG(ERROR) << "BigShift fails in BigMakeMont\n";
    return false;
  }
  return BigModMult(a, t1, m, mont_a);
}

// BigMontParams
//  Calculate m': RR'-mm'=1
bool BigMontParams(BigNum& m, int r, BigNum& m_prime) {
  int     n= (r+NBITSINUINT64-1)/NBITSINUINT64;
  if(m.size_>n)
    n= m.size_;
  BigNum  g(2*n+1);
  BigNum  R(2*n+1);
  BigNum  R_prime(2*n+1);
  BigNum  neg_m_prime(2*n+1);

  if(!BigShift(Big_One, r, R)) {
    LOG(ERROR) << "BigShift fails in BigMontParams\n";
    return false;
  }
  if(!BigExtendedGCD(m, R, neg_m_prime, R_prime, g)){
    LOG(ERROR) << "BigExtendedGCD fails in BigMontParams\n";
    return false;
  }
#if 0
  printf("g: "); PrintNumToConsole(g, 10); printf("\n");
  printf("m: "); PrintNumToConsole(m, 10); printf("\n");
  printf("R: "); PrintNumToConsole(R, 10); printf("\n");
  printf("R_prime: "); PrintNumToConsole(R_prime, 10); printf("\n");
  printf("neg_m_prime: "); PrintNumToConsole(neg_m_prime, 10); printf("\n");
#endif
  if(!BigModNormalize(neg_m_prime, R)) {
    LOG(ERROR) << "BigModNormalize fails in BigMontParams\n";
    return false;
  }
  if(!BigSub(R, neg_m_prime, m_prime)) {
    LOG(ERROR) << "BigSub fails in BigMontParams\n";
    return false;
  }
  return true;
}

// BigMontReduce(a,m,r)= a R^(-1) (mod m)
bool BigMontReduce(BigNum& a, int r, BigNum& m, BigNum& m_prime, BigNum& mont_a) {
  int     n= (r+NBITSINUINT64-1)/NBITSINUINT64;
  if(m.size_>n)
    n= m.size_;
  if(a.size_>n)
    n= a.size_;
  BigNum t(4*n+1);
  BigNum v(4*n+1);
  BigNum w(4*n+1);
  BigNum R(4*n+1);
  int     i;

  if(!BigMult(a, m_prime, t))
    return false;

  // reduce t mod 2^r
  int       k= r/NBITSINUINT64;
  uint64_t  u;

  for(i=(k+1);i<t.capacity_;i++)
    t.value_[i]= 0ULL;
  int l= r-(k*NBITSINUINT64);
  u= (0xffffffffffffffffULL)>>(NBITSINUINT64-l);
  t.value_[k]= t.value_[k]&u;
  t.Normalize();

  if(!BigMult(t, m, w)) {
    LOG(ERROR) << "BigMult error in BigMontReduce\n";
    return false;
  }
  if(!BigAdd(w, a, v)) {
    LOG(ERROR) << "BigAdd error in BigMontReduce\n";
    return false;
  }
  if(!BigShift(v, -r, mont_a)) {
    LOG(ERROR) << "BigShift error in BigMontReduce\n";
    return false;
  }
  if(BigCompare(m, mont_a)<=0) {
    if(!BigUnsignedSubFrom(mont_a, m)) {
      LOG(ERROR) << "BigUnsignedSubFrom error in BigMontReduce\n";
      return false;
    }
  }
  if(BigCompare(m, mont_a)<=0) {
    BigModNormalize(mont_a, m);
  }
  return true;
}

bool BigMontMult(BigNum& aR, BigNum& bR, BigNum& m, uint64_t r,
                 BigNum& m_prime, BigNum& abR) {
  int     n= (r+NBITSINUINT64-1)/NBITSINUINT64;
  if(m.size_>n)
    n= m.size_;
  if(aR.size_>n)
    n= aR.size_;
  if(bR.size_>n)
    n= bR.size_;


  BigNum  t(2*n+1);
  bool    ret= true;

  if(!BigUnsignedMult(aR, bR, t)) {
    LOG(ERROR)<< "BigMult fails in BigMontMult\n";
    ret= false;
  }
  if(ret && !BigMontReduce(t, r, m, m_prime, abR)) {
    LOG(ERROR)<< "BigMontReduce fails in BigMontMult\n";
    ret= false;
  }
  if(BigCompare(abR, m)>=0) {
    BigModNormalize(abR, m);
  }
  return ret;
}

/*
 *  MontExp
 *    Let Mont(a,b)= abR^-1 (mod p)
 *    R= b^r, m'= -m^(-1) (mod p), e= (e[t]...e[0])_2
 *    X= Mont(x, R^2(mod p))
 *    A= R (mod p)
 *    for(i=t; i>=0; i--) {
 *      A= Mont(A,A)
 *      if(e[i]==1) A= Mont(A,X)
 *    }
 *    A= Mont(A,1)
 *    return A
 */
bool BigMontExp(BigNum& b, BigNum& e, int r, BigNum& m, 
                BigNum& m_prime, BigNum& out) {
  int     n= (r+NBITSINUINT64-1)/NBITSINUINT64;
  if(m.size_>n)
    n= m.size_;
  if(b.size_>n)
    n= b.size_;
  if(e.size_>n)
    n= e.size_;

  BigNum  square(4*n+1);
  BigNum  accum(4*n+1);
  BigNum  t(4*n+1);
  int     k= BigHighBit(e); 
  int     i;

  if(!BigMakeMont(b, r, m, square)) {
    LOG(ERROR) << "BigMakeMont 1 fails in BigMontExp\n";
    return false;
  }
  if(!BigMakeMont(Big_One, r, m, accum)) {
    LOG(ERROR) << "BigMontMult 2 fails in BigMontExp " << m.size_ << ", " << square.size_ << "\n";
    return false;
  }
  for(i=1; i<=k; i++) {
    if(BigBitPositionOn(e, i)) {
      if(!BigMontMult(accum, square, m, r, m_prime, t)) {
        LOG(ERROR) << "BigMontMult 3 fails in BigMontExp " << m.size_ << ", " << square.size_ << "\n";
        return false;
      }
    accum.CopyFrom(t);
    }
    t.ZeroNum();
    if(i!=k) {
      if(!BigMontMult(square, square, m, r, m_prime, t)) {
          printf("b.size_: %d, square.size_: %d, m.size_: %d, m_prime.size_: %d\n", 
                 b.size_, square.size_, m.size_, m_prime.size_);
        LOG(ERROR) << "BigMontMult 4 fails in BigMontExp " << i<< " " << m.size_ << ", " << square.size_ << "\n";
        return false;
      }
      square.CopyFrom(t);
    }
  }
  return BigMontReduce(accum, r, m, m_prime, out);
}

