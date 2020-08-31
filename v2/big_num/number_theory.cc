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

#include "crypto_support.h"
#include "intel64_arith.h"

bool big_extended_gcd(big_num& a, big_num& b, big_num& x, big_num& y, big_num& g) {
  big_num* a_coeff[3] = {nullptr, nullptr, nullptr};
  big_num* b_coeff[3] = {nullptr, nullptr, nullptr};
  big_num* c[3] = {nullptr, nullptr, nullptr};

  int n = a.size_ > b.size_ ? a.size_ : b.size_;
  big_num q(2 * n + 1);
  big_num r(2 * n + 1);
  big_num t1(2 * n + 1);
  big_num t2(2 * n + 1);
  int old = 0;
  int current = 1;
  int next = 2;
  bool ret = true;
  int i;

  for (i = 0; i < 3; i++) {
    a_coeff[i] = new big_num(2 * n + 1);
    b_coeff[i] = new big_num(2 * n + 1);
    c[i] = new big_num(2 * n + 1);
  }

  a_coeff[0]->CopyFrom(big__one);
  b_coeff[0]->CopyFrom(big__Zero);
  a_coeff[1]->CopyFrom(big__Zero);
  b_coeff[1]->CopyFrom(big__one);
  a.CopyTo(*c[0]);
  b.CopyTo(*c[1]);

  for (;;) {
    r.ZeroNum();
    q.ZeroNum();
    t1.ZeroNum();
    t2.ZeroNum();

    // c[new]= q*c[old] +r;
    ret = big_UnsignedEuclid(*c[old], *c[current], q, r);
    if (!ret)
      goto done;
    if (r.IsZero())
      break;
    r.CopyTo(*c[next]);
    big_Mult(q, *a_coeff[current], t1);
    big_Mult(q, *b_coeff[current], t2);
    big_Sub(*a_coeff[old], t1, *a_coeff[next]);
    big_Sub(*b_coeff[old], t2, *b_coeff[next]);
    old = (old + 1) % 3;
    current = (current + 1) % 3;
    next = (next + 1) % 3;
  }

  a_coeff[current]->CopyTo(x);
  b_coeff[current]->CopyTo(y);
  c[current]->CopyTo(g);

done:
  for (i = 0; i < 3; i++) {
    if (a_coeff[i] != nullptr)
      delete a_coeff[i];
    a_coeff[i] = nullptr;
    if (b_coeff[i] != nullptr)
      delete b_coeff[i];
    b_coeff[i] = nullptr;
    if (c[i] != nullptr)
      delete c[i];
    c[i] = nullptr;
  }
  return ret;
}

bool big_CRT(big_num& s1, big_num& s2, big_num& m1, big_num& m2, big_num& r) {
  int m = m1.size_ > m2.size_ ? m1.size_ : m2.size_;
  if (s1.size_ > m)
    m = s1.size_;
  if (s2.size_ > m)
    m = s2.size_;
  big_num u1(3 * m + 1);
  big_num u2(3 * m + 1);
  big_num t1(3 * m + 1);
  big_num t2(3 * m + 1);
  big_num r1(3 * m + 1);
  big_num r2(3 * m + 1);
  big_num n(3 * m + 1);

  // u1 m1 + u2 m2= 1
  if (!big_extended_gcd(m1, m2, u1, u2, t1))
    return false;

  // r= u1 m1 s2 + u2 m2 s1
  if (!big_Mult(u1, m1, t1))
    return false;
  if (!big_Mult(t1, s2, r1))
    return false;
  if (!big_Mult(u2, m2, t2))
    return false;
  if (!big_Mult(t2, s1, r2))
    return false;
  if (!big_Mult(m1, m2, n))
    return false;
  if (!big_Add(r1, r2, r))
    return false;
  if (!big_ModNormalize(r, n))
    return false;
  return true;
}

bool big_Mod(big_num& a, big_num& m, big_num& r) {
  if (!r.CopyFrom(a))
    return false;
  if (!big_ModNormalize(r, m))
    return false;
  return true;
}

bool big_ModNormalize(big_num& a, big_num& m) {
  if (!a.sign_ && big_Compare(a, m) < 0)
    return true;

  int n = a.Capacity() > m.Capacity() ? a.Capacity() : m.Capacity();
  big_num t1(1 + 2 * n);
  big_num t2(1 + 2 * n);

  if (a.sign_) {
    if (!big_UnsignedEuclid(a, m, t1, t2))
      return false;
    if (!big_UnsignedAddTo(t1, big__one))
      return false;
    t2.ZeroNum();
    if (!big_UnsignedMult(t1, m, t2))
      return false;
    t1.ZeroNum();
    if (!big_Add(a, t2, t1))
      return false;
    t1.CopyTo(a);
  }
  if (a.sign_)
    return false;

  if (big_Compare(a, m) >= 0) {
    if (!big_UnsignedEuclid(a, m, t1, t2))
      return false;
    t2.Normalize();
    a.CopyFrom(t2);
    a.Normalize();
  }
  return true;
}

bool big_ModAdd(big_num& a, big_num& b, big_num& m, big_num& r) {
  if (!big_ModNormalize(a, m)) {
    return false;
  }
  if (!big_ModNormalize(b, m)) {
    return false;
  }
  if (!big_UnsignedAdd(a, b, r)) {
    return false;
  }
  if (!big_ModNormalize(r, m)) {
    return false;
  }
  return true;
}

bool big_ModNeg(big_num& a, big_num& m, big_num& r) {
  if (!a.CopyTo(r))
    return false;
  r.ToggleSign();
  if (!big_ModNormalize(r, m))
    return false;
  return true;
}

bool big_ModSub(big_num& a, big_num& b, big_num& m, big_num& r) {
  if (!big_ModNormalize(a, m)) {
    return false;
  }
  if (!big_ModNormalize(b, m)) {
    return false;
  }
  if (!big_Sub(a, b, r))
    return false;
  return big_ModNormalize(r, m);
}

bool checkbig_ModMult(big_num& ab, big_num& m, big_num& r) {
  big_num q(4 * m.capacity_ + 2);
  big_num nr(4 * m.capacity_ + 2);
  big_num ru(4 * m.capacity_ + 2);

  if (!big_UnsignedEuclid(ab, m, q, nr)) {
    printf("checkbig_ModMult, big_UnsignedEuclid failed\n");
    return false;
  }
  if (!big_UnsignedMult(m, q, ru)) {
    printf("checkbig_ModMult, big_UnsignedMult failed\n");
    return false;
  }
  if (!big_UnsignedAdd(ru, r, nr)) {
    printf("checkbig_ModMult, big_UnsignedAddfailed\n");
    return false;
  }
  if (big_Compare(ab, nr) != 0) {
    printf("checkbig_ModMult failed\n");
    printf("ab: ");
    PrintNumToConsole(ab, 16ULL);
    printf("\n");
    printf("nr: ");
    PrintNumToConsole(nr, 16ULL);
    printf("\n");
    return false;
  }
  return true;
}

bool big_ModMult(big_num& a, big_num& b, big_num& m, big_num& r) {
  int n = a.size_ > b.size_ ? a.size_ : b.size_;

  if (m.size_ > n) n = m.size_;
  if (!big_ModNormalize(a, m))
    return false;
  if (!big_ModNormalize(b, m))
    return false;
  big_num t(2 * n + 2);
  if (!big_UnsignedMult(a, b, t))
    return false;
  return big_Mod(t, m, r);
}

bool big_ModSquare(big_num& a, big_num& m, big_num& r) {
  return big_ModMult(a, a, m, r);
}

bool big_ModInv(big_num& a, big_num& m, big_num& r) {
  big_num x(2 * m.capacity_ + 1);
  big_num y(2 * m.capacity_ + 1);
  big_num g(2 * m.capacity_ + 1);

  if (!big_ModNormalize(a, m))
    return false;
  if (!big_extended_gcd(a, m, x, y, g))
    return false;
  r.CopyFrom(x);
  return big_ModNormalize(r, m);
}

// r= a/b
bool big_ModDiv(big_num& a, big_num& b, big_num& m, big_num& r) {
  int n = a.size_ > b.size_ ? a.size_ : b.size_;
  if (m.size_ > n)
    n = m.size_;
  big_num x(3 * n + 1);

  if (!big_ModInv(b, m, x))
    return false;
  if (!big_ModMult(a, x, m, r))
    return false;
  return big_ModNormalize(r, m);
}

bool big_ModExp(big_num& a, big_num& e, big_num& m, big_num& r) {
  big_num* accum[2] = {nullptr, nullptr};
  big_num* doubled[2] = {nullptr, nullptr};
  int accum_current = 0;
  int accum_next = 1;
  int doubler_current = 0;
  int doubler_next = 1;
  bool ret = true;
  int i;
  int k;
  big_num b(a);

  if (!big_ModNormalize(b, m))
    return false;

  k = big_HighBit(e);
  if (k == 0) {
    big__one.CopyTo(r);
    goto done;
  }
  for (i = 0; i < 2; i++) {
    accum[i] = new big_num(4 * m.Capacity() + 1);
    doubled[i] = new big_num(4 * m.Capacity() + 1);
  }
  accum[accum_current]->CopyFrom(big__one);
  doubled[doubler_current]->CopyFrom(b);
  for (i = 1; i < k; i++) {
    if (big_BitPositionOn(e, i)) {
      accum[accum_next]->ZeroNum();
      if (!big_ModMult(*accum[accum_current], *doubled[doubler_current], m,
                      *accum[accum_next])) {
        ret = false;
        goto done;
      }
      accum_current = (accum_current + 1) % 2;
      accum_next = (accum_next + 1) % 2;
    }
    doubled[doubler_next]->ZeroNum();
    if (!big_ModSquare(*doubled[doubler_current], m, *doubled[doubler_next])) {
      ret = false;
      goto done;
    }
    doubler_current = (doubler_current + 1) % 2;
    doubler_next = (doubler_next + 1) % 2;
  }
  if (big_BitPositionOn(e, i)) {
    accum[accum_next]->ZeroNum();
    big_ModMult(*accum[accum_current], *doubled[doubler_current], m,
               *accum[accum_next]);
    accum_current = (accum_current + 1) % 2;
    accum_next = (accum_next + 1) % 2;
  }
  if (ret) {
    r.CopyFrom(*accum[accum_current]);
    ret = big_ModNormalize(r, m);
#if 0
    checkbig_ModMult(*accum[accum_current], m, r);
#endif
  }

done:
  for (i = 0; i < 2; i++) {
    if (accum[i] != nullptr) {
      delete accum[i];
    }
    if (doubled[i] != nullptr) {
      delete doubled[i];
    }
  }
  return ret;
}

#define MAXPRIMETRYS 25000

bool big_GenPrime(big_num& p, uint64_t num_bits) {
  int i, j;

  for (i = 0; i < MAXPRIMETRYS; i++) {
    p.ZeroNum();
    if (!GetCryptoRand(num_bits, (byte*)p.value_)) {
      return false;
    }
    p.value_[p.size_ - 1] |= (1ULL) << 63;
    p.value_[0] |= 1ULL;
    p.Normalize();
    for (j = 0; j < 250; j++, i++) {
      if (big_IsPrime(p)) {
        return true;
      }
      if (!big_UnsignedAddTo(p, big__Two)) {
        return false;
      }
    }
  }
  return false;
}

bool rands_avail = false;
big_num* random_nums[40];

bool FillRandom(int n, big_num** random_array) {
  int i;

  if (n > 20)
    return false;

  if (!rands_avail) {
    random_nums[0] = new big_num(5, 2ULL);
    for (i = 0; i < 19; i++) {
      random_nums[i + 1] = new big_num(5, 2ULL + (uint64_t)(19 * i));
      random_nums[i + 1]->Normalize();
    }
    rands_avail = true;
  }
  for (i = 0; i < 20; i++) {
    random_array[i] = random_nums[i];
  }

  return true;
}

bool big_MillerRabin(big_num& n, big_num** random_a, int trys) {
  big_num n_minus_1(2 * n.size_);
  big_num odd_part_n_minus_1(2 * n.size_);
  big_num y(4 * n.size_ + 1);
  big_num z(4 * n.size_ + 1);
  int i;
  int j;
  int shift;

  if (!big_Sub(n, big__one, n_minus_1))
    return false;
  shift = big_MaxPowerOfTwoDividing(n_minus_1);
  if (shift > 0) {
    if (!big_Shift(n_minus_1, -shift, odd_part_n_minus_1))
      return false;
  }
  for (i = 0; i < trys; i++) {
    y.ZeroNum();
    if (!big_ModExp(*random_a[i], odd_part_n_minus_1, n, y))
      return false;
    if (big_Compare(y, big__one) == 0 || big_Compare(y, n_minus_1) == 0)
      continue;
    for (j = 0; j < shift; j++) {
      z.ZeroNum();
      if (!big_ModMult(y, y, n, z))
        return false;
      if (big_Compare(z, big__one) == 0)
        return false;
    }
    y.CopyFrom(z);
    if (big_Compare(y, n_minus_1) == 0)
      break;
  }
  if (big_Compare(y, n_minus_1) != 0)
    return false;
  return true;
}

bool big_IsPrime(big_num& n) {
  extern uint64_t smallest_primes[];
  extern int num_smallest_primes;
  int i, k, m;
  uint64_t q[n.size_];
  uint64_t r;
  big_num** random_a = new big_num* [20];

  for (i = 0; i < num_smallest_primes; i++) {
    if (n.size_ == 1 && smallest_primes[i] >= n.value_[0])
      return true;
    k = n.size_;
    m = DigitArrayShortDivisionAlgorithm(
        n.size_, n.value_, (uint64_t)smallest_primes[i], &k, q, &r);
    if (m < 0) {
      return false;
    }
    if (r == 0ULL)
      return false;
  }
  if (!FillRandom(20, random_a)) {
    return false;
  }
  return big_MillerRabin(n, random_a);
}

bool big_ModIsSquare(big_num& n, big_num& p) {
  big_num p_minus_1(n.Size());
  big_num e(n.Size());
  int m = (n.Capacity() > p.Capacity()) ? n.Capacity() : p.Capacity();
  big_num residue(4 * m + 1);
  uint64_t unused;
  int size_e;

  big_Sub(p, big__one, p_minus_1);
  size_e = DigitArrayComputedSize(p_minus_1.size_, p_minus_1.value_);
  int k = DigitArrayShortDivisionAlgorithm(p_minus_1.size_, p_minus_1.value_,
                                           2ULL, &size_e, e.value_, &unused);
  e.size_ = size_e;
  if (k < 0) {
    return false;
  }
  e.size_ = DigitArrayComputedSize(e.size_, e.value_);
  if (!big_ModExp(n, e, p, residue)) {
    return false;
  }
  if (!residue.Isone())
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
int smallestunitaryexponent(big_num& b, big_num& p, int maxm) {
  big_num e(2 * p.capacity_ + 1);
  big_num t(2 * p.capacity_ + 1);
  int i;

  for (i = 1; i < maxm; i++) {
    if (!big_Shift(big__one, i, e))
      return -1;
    if (!big_ModExp(b, e, p, t))
      return -1;
    if (big_Compare(big__one, t) == 0) {
      break;
    }
    e.ZeroNum();
    t.ZeroNum();
  }

  return i;
}

bool big_ModTonelliShanks(big_num& a, big_num& p, big_num& s) {
  big_num t1(2 * p.size_ + 1);
  big_num t2(2 * p.size_ + 1);

  big_num q(2 * p.size_ + 1);  // p-1= 2^max_two_power q
  big_num p_minus(2 * p.size_ + 1);

  int max_two_power;
  int m;

  big_num e(2 * p.size_ + 1);  // exponent
  big_num n(2 * p.size_ + 1);  // non-residue
  big_num x(2 * p.size_ + 1);
  big_num y(2 * p.size_ + 1);
  big_num z(2 * p.size_ + 1);
  big_num b(2 * p.size_ + 1);
  big_num t(2 * p.size_ + 1);

  if (!big_UnsignedSub(p, big__one, p_minus)) {
    return false;
  }
  max_two_power = big_MaxPowerOfTwoDividing(p_minus);
  if (!big_Shift(p_minus, -max_two_power, q)) {
    return false;
  }
  n.value_[0] = 2ULL;
  while (!big_ModIsSquare(n, p)) {
    if (!big_UnsignedAddTo(n, big__one)) {
      return false;
    }
  }
  if (!big_ModExp(n, q, p, z)) {
    return false;
  }
  if (!z.CopyTo(y)) {
    return false;
  }
  if (!big_UnsignedSub(q, big__one, t1)) {
    return false;
  }
  if (!big_Shift(t1, -1, t2)) {
    return false;
  }
  if (!big_ModExp(a, t2, p, x)) {
    return false;
  }
  t1.ZeroNum();
  t2.ZeroNum();
  if (!big_ModMult(x, x, p, t1)) {
    return false;
  }
  if (!big_ModMult(t1, a, p, b)) {
    return false;
  }
  t1.ZeroNum();
  if (!big_ModMult(x, a, p, t1)) {
    return false;
  }
  t1.CopyTo(x);

  for (;;) {
    if (big_Compare(big__one, b) == 0)
      break;
    // at this point ab= x^2, y^(2^(r-1))= -1 (mod p), b^(2^(r-1)) =1

    // find smallest m: b^(2^m)= 1 (mod p) --- note m<r
    m = smallestunitaryexponent(b, p, max_two_power);

    // t=y^(2^(r-m-1)) (mod p)
    if (!big_Shift(big__one, max_two_power - m - 1, e)) {
      return false;
    }
    if (!big_ModExp(y, t2, p, t)) {
      return false;
    }
    y.ZeroNum();

    // y= t^2
    if (!big_ModMult(t, t, p, y)) {
      return false;
    }
    // r= m; x=xt; b=by;
    max_two_power = m;
    t1.ZeroNum();
    if (!big_ModMult(x, t, p, t1)) {
      return false;
    }
    t1.CopyTo(x);
    t1.ZeroNum();
    if (!big_ModMult(y, b, p, t1)) {
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
bool big_ModSquareRoot(big_num& n, big_num& p, big_num& r) {
  uint64_t bot = p.value_[0] & 0x7;
  big_num p_temp(p.size_);

  if (bot == 1)
    return big_ModTonelliShanks(n, p, r);

  big_num t1(1 + 2 * p.size_);
  big_num t2(1 + 2 * p.size_);
  big_num t3(1 + 2 * p.size_);
  if (bot == 3 || bot == 7) {
    if (!big_UnsignedAdd(p, big__one, p_temp)) {
      return false;
    }
    if (!big_Shift(p_temp, -2, t1)) {
      return false;
    }
    if (!big_ModExp(n, t1, p, r)) {
      return false;
    }
  } else if (bot == 5) {
    if (!big_UnsignedSub(p, big__one, p_temp)) {
      return false;
    }
    if (!big_Shift(p_temp, -2, t1)) {
      return false;
    }
    if (!big_ModExp(n, t1, p, t2)) {
      return false;
    }

    if (big_Compare(big__one, t2) == 0) {
      p_temp.ZeroNum();
      // if(b==1) x= a^((p+3)/8) (mod p)
      p_temp.ZeroNum();
      t1.ZeroNum();
      if (!big_UnsignedAdd(p, big__Three, p_temp)) {
        return false;
      }
      if (!big_Shift(p_temp, -3, t1)) {
        return false;
      }
      if (!big_ModExp(n, t1, p, r)) {
        return false;
      }
    } else {
      t1.ZeroNum();
      t2.ZeroNum();
      t3.ZeroNum();
      p_temp.ZeroNum();
      //  otherwise, x= (2a)(4a)^((p-5)/8)
      if (!big_UnsignedSub(p, big__Five, p_temp)) {
        return false;
      }
      if (!big_Shift(p_temp, -3, t1)) {
        return false;
      }
      if (!big_Shift(n, 2, t2)) {
        return false;
      }
      if (!big_ModExp(t2, t1, p, t3)) {
        return false;
      }
      t1.ZeroNum();
      t2.ZeroNum();
      if (!big_Shift(n, 1, t2)) {
        return false;
      }
      if (!big_ModMult(t2, t3, p, r)) {
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

// big_MakeMont(a,m,r)= a R (mod m)
bool big_MakeMont(big_num& a, int r, big_num& m, big_num& mont_a) {
  int n = a.size_ > m.size_ ? a.size_ : m.size_;
  int k = (r + NBITSINUINT64 - 1) / NBITSINUINT64;
  if (k > n)
    n = k;

  big_num t1(1 + 2 * n);

  if (m.IsZero()) {
    return false;
  }
  if (!big_Shift(big__one, r, t1)) {
    return false;
  }
  return big_ModMult(a, t1, m, mont_a);
}

// big_MontParams
//  Calculate m': RR'-mm'=1
bool big_MontParams(big_num& m, int r, big_num& m_prime) {
  int n = (r + NBITSINUINT64 - 1) / NBITSINUINT64;
  if (m.size_ > n)
    n = m.size_;
  big_num g(2 * n + 1);
  big_num R(2 * n + 1);
  big_num R_prime(2 * n + 1);
  big_num neg_m_prime(2 * n + 1);

  if (!big_Shift(big__one, r, R)) {
    return false;
  }
  if (!big_extended_gcd(m, R, neg_m_prime, R_prime, g)) {
    return false;
  }
  if (!big_ModNormalize(neg_m_prime, R)) {
    return false;
  }
  if (!big_Sub(R, neg_m_prime, m_prime)) {
    return false;
  }
  return true;
}

// big_MontReduce(a,m,r)= a R^(-1) (mod m)
bool big_MontReduce(big_num& a, int r, big_num& m, big_num& m_prime,
                   big_num& mont_a) {
  int n = (r + NBITSINUINT64 - 1) / NBITSINUINT64;
  if (m.size_ > n)
    n = m.size_;
  if (a.size_ > n)
    n = a.size_;
  big_num t(4 * n + 1);
  big_num v(4 * n + 1);
  big_num w(4 * n + 1);
  big_num R(4 * n + 1);
  int i;

  if (!big_Mult(a, m_prime, t))
    return false;

  // reduce t mod 2^r
  int k = r / NBITSINUINT64;
  uint64_t u;

  for (i = (k + 1); i < t.capacity_; i++) t.value_[i] = 0ULL;
  int l = r - (k * NBITSINUINT64);
  u = (0xffffffffffffffffULL) >> (NBITSINUINT64 - l);
  t.value_[k] = t.value_[k] & u;
  t.Normalize();

  if (!big_Mult(t, m, w)) {
    return false;
  }
  if (!big_Add(w, a, v)) {
    return false;
  }
  if (!big_Shift(v, -r, mont_a)) {
    return false;
  }
  if (big_Compare(m, mont_a) <= 0) {
    if (!big_UnsignedSubFrom(mont_a, m)) {
      return false;
    }
  }
  if (big_Compare(m, mont_a) <= 0) {
    // shouldn't need this
    big_ModNormalize(mont_a, m);
  }
  return true;
}

bool big_MontMult(big_num& aR, big_num& bR, big_num& m, uint64_t r, big_num& m_prime,
                 big_num& abR) {
  int n = (r + NBITSINUINT64 - 1) / NBITSINUINT64;
  if (m.size_ > n)
    n = m.size_;
  if (aR.size_ > n)
    n = aR.size_;
  if (bR.size_ > n)
    n = bR.size_;

  big_num t(2 * n + 1);
  bool ret = true;

  if (!big_UnsignedMult(aR, bR, t)) {
    ret = false;
  }
  if (ret && !big_MontReduce(t, r, m, m_prime, abR)) {
    ret = false;
  }
  if (big_Compare(abR, m) >= 0) {
    // shouldn't need this
    big_ModNormalize(abR, m);
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
bool big_MontExp(big_num& b, big_num& e, int r, big_num& m, big_num& m_prime,
                big_num& out) {
  int n = (r + NBITSINUINT64 - 1) / NBITSINUINT64;
  if (m.size_ > n)
    n = m.size_;
  if (b.size_ > n)
    n = b.size_;
  if (e.size_ > n)
    n = e.size_;

  big_num square(4 * n + 1);
  big_num accum(4 * n + 1);
  big_num t(4 * n + 1);
  int k = big_HighBit(e);
  int i;

  if (!big_MakeMont(b, r, m, square)) {
    return false;
  }
  if (!big_MakeMont(big__one, r, m, accum)) {
               << square.size_ << "\n";
    return false;
  }
  for (i = 1; i <= k; i++) {
    if (big_BitPositionOn(e, i)) {
      if (!big_MontMult(accum, square, m, r, m_prime, t)) {
                   << square.size_ << "\n";
        return false;
      }
      accum.CopyFrom(t);
    }
    t.ZeroNum();
    if (i != k) {
      if (!big_MontMult(square, square, m, r, m_prime, t)) {
        printf(
            "b.size_: %d, square.size_: %d, m.size_: %d, m_prime.size_: %d\n",
            b.size_, square.size_, m.size_, m_prime.size_);
        return false;
      }
      square.CopyFrom(t);
    }
  }
  return big_MontReduce(accum, r, m, m_prime, out);
}
