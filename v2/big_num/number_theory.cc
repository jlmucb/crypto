//
// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: number_theory.cc

#include "crypto_support.h"
#include "big_num.h"
#include "intel_digit_arith.h"
#include "big_num_functions.h"

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

  a_coeff[0]->copy_from(big_one);
  b_coeff[0]->copy_from(big_zero);
  a_coeff[1]->copy_from(big_zero);
  b_coeff[1]->copy_from(big_one);
  a.copy_to(*c[0]);
  b.copy_to(*c[1]);

  for (;;) {
    r.zero_num();
    q.zero_num();
    t1.zero_num();
    t2.zero_num();

    // c[new]= q*c[old] +r;
    ret = big_unsigned_euclid(*c[old], *c[current], q, r);
    if (!ret)
      goto done;
    if (r.is_zero())
      break;
    r.copy_to(*c[next]);
    big_mult(q, *a_coeff[current], t1);
    big_mult(q, *b_coeff[current], t2);
    big_sub(*a_coeff[old], t1, *a_coeff[next]);
    big_sub(*b_coeff[old], t2, *b_coeff[next]);
    old = (old + 1) % 3;
    current = (current + 1) % 3;
    next = (next + 1) % 3;
  }

  a_coeff[current]->copy_to(x);
  b_coeff[current]->copy_to(y);
  c[current]->copy_to(g);

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

bool big_crt(big_num& s1, big_num& s2, big_num& m1, big_num& m2, big_num& r) {
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
  if (!big_mult(u1, m1, t1))
    return false;
  if (!big_mult(t1, s2, r1))
    return false;
  if (!big_mult(u2, m2, t2))
    return false;
  if (!big_mult(t2, s1, r2))
    return false;
  if (!big_mult(m1, m2, n))
    return false;
  if (!big_add(r1, r2, r))
    return false;
  if (!big_mod_normalize(r, n))
    return false;
  return true;
}

bool big_mod(big_num& a, big_num& m, big_num& r) {
  if (!r.copy_from(a))
    return false;
  if (!big_mod_normalize(r, m))
    return false;
  return true;
}

bool big_mod_normalize(big_num& a, big_num& m) {
  if (!a.sign_ && big_compare(a, m) < 0)
    return true;

  int n = a.capacity() > m.capacity() ? a.capacity() : m.capacity();
  big_num t1(1 + 2 * n);
  big_num t2(1 + 2 * n);

  if (a.sign_) {
    if (!big_unsigned_euclid(a, m, t1, t2))
      return false;
    if (!big_unsigned_add_to(t1, big_one))
      return false;
    t2.zero_num();
    if (!big_unsigned_mult(t1, m, t2))
      return false;
    t1.zero_num();
    if (!big_add(a, t2, t1))
      return false;
    t1.copy_to(a);
  }
  if (a.sign_)
    return false;

  if (big_compare(a, m) >= 0) {
    if (!big_unsigned_euclid(a, m, t1, t2))
      return false;
    t2.normalize();
    a.copy_from(t2);
    a.normalize();
  }
  return true;
}

bool big_mod_add(big_num& a, big_num& b, big_num& m, big_num& r) {
  if (!big_mod_normalize(a, m)) {
    return false;
  }
  if (!big_mod_normalize(b, m)) {
    return false;
  }
  if (!big_unsigned_add(a, b, r)) {
    return false;
  }
  if (!big_mod_normalize(r, m)) {
    return false;
  }
  return true;
}

bool big_mod_neg(big_num& a, big_num& m, big_num& r) {
  if (!a.copy_to(r))
    return false;
  r.toggle_sign();
  if (!big_mod_normalize(r, m))
    return false;
  return true;
}

bool big_mod_sub(big_num& a, big_num& b, big_num& m, big_num& r) {
  if (!big_mod_normalize(a, m)) {
    return false;
  }
  if (!big_mod_normalize(b, m)) {
    return false;
  }
  if (!big_sub(a, b, r))
    return false;
  return big_mod_normalize(r, m);
}

bool check_big_mod_mult(big_num& ab, big_num& m, big_num& r) {
  big_num q(4 * m.capacity_ + 2);
  big_num nr(4 * m.capacity_ + 2);
  big_num ru(4 * m.capacity_ + 2);

  if (!big_unsigned_euclid(ab, m, q, nr)) {
    printf("check_big_mod_mult, big_unsigned_euclid failed\n");
    return false;
  }
  if (!big_unsigned_mult(m, q, ru)) {
    printf("check_big_mod_mult, big_unsigned_mult failed\n");
    return false;
  }
  if (!big_unsigned_add(ru, r, nr)) {
    printf("check_big_mod_mult, big_unsigned_addfailed\n");
    return false;
  }
  if (big_compare(ab, nr) != 0) {
    printf("check_big_mod_mult failed\n");
    return false;
  }
  return true;
}

bool big_mod_mult(big_num& a, big_num& b, big_num& m, big_num& r) {
  int n = a.size_ > b.size_ ? a.size_ : b.size_;

  if (m.size_ > n) n = m.size_;
  if (!big_mod_normalize(a, m))
    return false;
  if (!big_mod_normalize(b, m))
    return false;
  big_num t(2 * n + 2);
  if (!big_unsigned_mult(a, b, t))
    return false;
  return big_mod(t, m, r);
}

bool big_mod_square(big_num& a, big_num& m, big_num& r) {
  return big_mod_mult(a, a, m, r);
}

bool big_mod_inv(big_num& a, big_num& m, big_num& r) {
  big_num x(2 * m.capacity_ + 1);
  big_num y(2 * m.capacity_ + 1);
  big_num g(2 * m.capacity_ + 1);

  if (!big_mod_normalize(a, m))
    return false;
  if (!big_extended_gcd(a, m, x, y, g))
    return false;
  r.copy_from(x);
  return big_mod_normalize(r, m);
}

// r= a/b
bool big_mod_div(big_num& a, big_num& b, big_num& m, big_num& r) {
  int n = a.size_ > b.size_ ? a.size_ : b.size_;
  if (m.size_ > n)
    n = m.size_;
  big_num x(3 * n + 1);

  if (!big_mod_inv(b, m, x))
    return false;
  if (!big_mod_mult(a, x, m, r))
    return false;
  return big_mod_normalize(r, m);
}

bool big_mod_exp(big_num& a, big_num& e, big_num& m, big_num& r) {
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

  if (!big_mod_normalize(b, m))
    return false;

  k = big_high_bit(e);
  if (k == 0) {
    big_one.copy_to(r);
    goto done;
  }
  for (i = 0; i < 2; i++) {
    accum[i] = new big_num(4 * m.capacity() + 1);
    doubled[i] = new big_num(4 * m.capacity() + 1);
  }
  accum[accum_current]->copy_from(big_one);
  doubled[doubler_current]->copy_from(b);
  for (i = 1; i < k; i++) {
    if (big_bit_position_on(e, i)) {
      accum[accum_next]->zero_num();
      if (!big_mod_mult(*accum[accum_current], *doubled[doubler_current], m,
                      *accum[accum_next])) {
        ret = false;
        goto done;
      }
      accum_current = (accum_current + 1) % 2;
      accum_next = (accum_next + 1) % 2;
    }
    doubled[doubler_next]->zero_num();
    if (!big_mod_square(*doubled[doubler_current], m, *doubled[doubler_next])) {
      ret = false;
      goto done;
    }
    doubler_current = (doubler_current + 1) % 2;
    doubler_next = (doubler_next + 1) % 2;
  }
  if (big_bit_position_on(e, i)) {
    accum[accum_next]->zero_num();
    big_mod_mult(*accum[accum_current], *doubled[doubler_current], m,
               *accum[accum_next]);
    accum_current = (accum_current + 1) % 2;
    accum_next = (accum_next + 1) % 2;
  }
  if (ret) {
    r.copy_from(*accum[accum_current]);
    ret = big_mod_normalize(r, m);
#if 0
    check_big_mod_mult(*accum[accum_current], m, r);
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

bool big_gen_prime(big_num& p, uint64_t num_bits, int prime_trys) {
  int i, j;

  for (i = 0; i < MAXPRIMETRYS; i++) {
    p.zero_num();
    if (big_num_get_random((num_bits + NBITSINBYTE -1) / NBITSINBYTE, (byte*)p.value_) < 0)
      return false;
    p.value_[p.size_ - 1] |= (1ULL) << 63;
    p.value_[0] |= 1ULL;
    p.normalize();
    for (j = 0; j < 250; j++, i++) {
      if (big_is_prime(p)) {
        return true;
      }
      if (!big_unsigned_add_to(p, big_two)) {
        return false;
      }
    }
  }
  return false;
}

bool big_miller_rabin(big_num& n, big_num** random_a, int trys) {
  big_num n_minus_1(2 * n.size_);
  big_num odd_part_n_minus_1(2 * n.size_);
  big_num y(4 * n.size_ + 1);
  big_num z(4 * n.size_ + 1);
  int i;
  int j;
  int shift;

  if (!big_sub(n, big_one, n_minus_1))
    return false;
  shift = big_max_power_of_two_dividing(n_minus_1);
  if (shift > 0) {
    if (!big_shift(n_minus_1, -shift, odd_part_n_minus_1))
      return false;
  }
  for (i = 0; i < trys; i++) {
    y.zero_num();
    if (!big_mod_exp(*random_a[i], odd_part_n_minus_1, n, y))
      return false;
    if (big_compare(y, big_one) == 0 || big_compare(y, n_minus_1) == 0)
      continue;
    for (j = 0; j < shift; j++) {
      z.zero_num();
      if (!big_mod_mult(y, y, n, z))
        return false;
      if (big_compare(z, big_one) == 0)
        return false;
    }
    y.copy_from(z);
    if (big_compare(y, n_minus_1) == 0)
      break;
  }
  if (big_compare(y, n_minus_1) != 0)
    return false;
  return true;
}

bool big_is_prime(big_num& n) {
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
    m = digit_array_short_division_algorithm(
        n.size_, n.value_, (uint64_t)smallest_primes[i], &k, q, &r);
    if (m < 0) {
      return false;
    }
    if (r == 0ULL)
      return false;
  }
  for (int j = 0; j < 20; j++) {
    random_a[j] = new big_num(20);
    if (big_num_get_random(32, (byte*)random_a[j]->value_ptr()) < 0)
      return false;
    random_a[j]->normalize();
  }
  return big_miller_rabin(n, random_a, 20);
}

bool big_mod_is_square(big_num& n, big_num& p) {
  big_num p_minus_1(n.size());
  big_num e(n.size());
  int m = (n.capacity() > p.capacity()) ? n.capacity() : p.capacity();
  big_num residue(4 * m + 1);
  uint64_t unused;
  int size_e;

  big_sub(p, big_one, p_minus_1);
  size_e = digit_array_real_size(p_minus_1.size_, p_minus_1.value_);
  int k = digit_array_short_division_algorithm(p_minus_1.size_, p_minus_1.value_,
                                           2ULL, &size_e, e.value_, &unused);
  e.size_ = size_e;
  if (k < 0) {
    return false;
  }
  e.size_ = digit_array_real_size(e.size_, e.value_);
  if (!big_mod_exp(n, e, p, residue)) {
    return false;
  }
  if (!residue.is_one())
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
int smallest_unitary_exponent(big_num& b, big_num& p, int maxm) {
  big_num e(2 * p.capacity_ + 1);
  big_num t(2 * p.capacity_ + 1);
  int i;

  for (i = 1; i < maxm; i++) {
    if (!big_shift(big_one, i, e))
      return -1;
    if (!big_mod_exp(b, e, p, t))
      return -1;
    if (big_compare(big_one, t) == 0) {
      break;
    }
    e.zero_num();
    t.zero_num();
  }

  return i;
}

bool big_mod_tonelli_shanks(big_num& a, big_num& p, big_num& s) {
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

  if (!big_unsigned_sub(p, big_one, p_minus)) {
    return false;
  }
  max_two_power = big_max_power_of_two_dividing(p_minus);
  if (!big_shift(p_minus, -max_two_power, q)) {
    return false;
  }
  n.value_[0] = 2ULL;
  while (!big_mod_is_square(n, p)) {
    if (!big_unsigned_add_to(n, big_one)) {
      return false;
    }
  }
  if (!big_mod_exp(n, q, p, z)) {
    return false;
  }
  if (!z.copy_to(y)) {
    return false;
  }
  if (!big_unsigned_sub(q, big_one, t1)) {
    return false;
  }
  if (!big_shift(t1, -1, t2)) {
    return false;
  }
  if (!big_mod_exp(a, t2, p, x)) {
    return false;
  }
  t1.zero_num();
  t2.zero_num();
  if (!big_mod_mult(x, x, p, t1)) {
    return false;
  }
  if (!big_mod_mult(t1, a, p, b)) {
    return false;
  }
  t1.zero_num();
  if (!big_mod_mult(x, a, p, t1)) {
    return false;
  }
  t1.copy_to(x);

  for (;;) {
    if (big_compare(big_one, b) == 0)
      break;
    // at this point ab= x^2, y^(2^(r-1))= -1 (mod p), b^(2^(r-1)) =1

    // find smallest m: b^(2^m)= 1 (mod p) --- note m<r
    m = smallest_unitary_exponent(b, p, max_two_power);

    // t=y^(2^(r-m-1)) (mod p)
    if (!big_shift(big_one, max_two_power - m - 1, e)) {
      return false;
    }
    if (!big_mod_exp(y, t2, p, t)) {
      return false;
    }
    y.zero_num();

    // y= t^2
    if (!big_mod_mult(t, t, p, y)) {
      return false;
    }
    // r= m; x=xt; b=by;
    max_two_power = m;
    t1.zero_num();
    if (!big_mod_mult(x, t, p, t1)) {
      return false;
    }
    t1.copy_to(x);
    t1.zero_num();
    if (!big_mod_mult(y, b, p, t1)) {
      return false;
    }
    t1.copy_to(y);
  }
  return true;
}

//  a>0, p!=2
//  Find x: x^2=n (mod p)
//  if(p==3 (mod 4)) x= a^((p+1)/4 (mod p)
//  if(p==5 (mod 8)) put b= n^((p-1)/4) (mod p)
//    if(b==1) x= a^((p+3)/8) (mod p)
//    otherwise, x= (2a)(4a)^((p-5)/8)
//  in all other cases, apply Tonneli-Shanks
bool big_mod_square_root(big_num& n, big_num& p, big_num& r) {
  uint64_t bot = p.value_[0] & 0x7;
  big_num p_temp(p.size_);

  if (bot == 1)
    return big_mod_tonelli_shanks(n, p, r);

  big_num t1(1 + 2 * p.size_);
  big_num t2(1 + 2 * p.size_);
  big_num t3(1 + 2 * p.size_);
  if (bot == 3 || bot == 7) {
    if (!big_unsigned_add(p, big_one, p_temp)) {
      return false;
    }
    if (!big_shift(p_temp, -2, t1)) {
      return false;
    }
    if (!big_mod_exp(n, t1, p, r)) {
      return false;
    }
  } else if (bot == 5) {
    if (!big_unsigned_sub(p, big_one, p_temp)) {
      return false;
    }
    if (!big_shift(p_temp, -2, t1)) {
      return false;
    }
    if (!big_mod_exp(n, t1, p, t2)) {
      return false;
    }

    if (big_compare(big_one, t2) == 0) {
      p_temp.zero_num();
      // if(b==1) x= a^((p+3)/8) (mod p)
      p_temp.zero_num();
      t1.zero_num();
      if (!big_unsigned_add(p, big_three, p_temp)) {
        return false;
      }
      if (!big_shift(p_temp, -3, t1)) {
        return false;
      }
      if (!big_mod_exp(n, t1, p, r)) {
        return false;
      }
    } else {
      t1.zero_num();
      t2.zero_num();
      t3.zero_num();
      p_temp.zero_num();
      //  otherwise, x= (2a)(4a)^((p-5)/8)
      if (!big_unsigned_sub(p, big_five, p_temp)) {
        return false;
      }
      if (!big_shift(p_temp, -3, t1)) {
        return false;
      }
      if (!big_shift(n, 2, t2)) {
        return false;
      }
      if (!big_mod_exp(t2, t1, p, t3)) {
        return false;
      }
      t1.zero_num();
      t2.zero_num();
      if (!big_shift(n, 1, t2)) {
        return false;
      }
      if (!big_mod_mult(t2, t3, p, r)) {
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
 *  multiply.  0<= x, y <p.  R=b^n.  output: xyR^(-1) (mod p)
 *    A= 0
 *    for(i=0;i<n; i++) {
 *      u[i]= (a[0]+x[i]y[0]) p' mod b  (b is base, R=b^n)
 *      A= A+u[i]y[0] (mod b)
 *      A= (A+x[i]y+u[i]m)/b
 *    }
 *    if(A>=p)  A-= p
 *    return A
 */

// big_make_mont(a,m,r)= a R (mod m)
bool big_make_mont(big_num& a, int r, big_num& m, big_num& mont_a) {
  int n = a.size_ > m.size_ ? a.size_ : m.size_;
  int k = (r + NBITSINUINT64 - 1) / NBITSINUINT64;
  if (k > n)
    n = k;

  big_num t1(1 + 2 * n);

  if (m.is_zero()) {
    return false;
  }
  if (!big_shift(big_one, r, t1)) {
    return false;
  }
  return big_mod_mult(a, t1, m, mont_a);
}

// big_mont_params
//  Calculate m': RR'-mm'=1
bool big_mont_params(big_num& m, int r, big_num& m_prime) {
  int n = (r + NBITSINUINT64 - 1) / NBITSINUINT64;
  if (m.size_ > n)
    n = m.size_;
  big_num g(2 * n + 1);
  big_num R(2 * n + 1);
  big_num R_prime(2 * n + 1);
  big_num neg_m_prime(2 * n + 1);

  if (!big_shift(big_one, r, R)) {
    return false;
  }
  if (!big_extended_gcd(m, R, neg_m_prime, R_prime, g)) {
    return false;
  }
  if (!big_mod_normalize(neg_m_prime, R)) {
    return false;
  }
  if (!big_sub(R, neg_m_prime, m_prime)) {
    return false;
  }
  return true;
}

// big_mont_reduce(a,m,r)= a R^(-1) (mod m)
bool big_mont_reduce(big_num& a, int r, big_num& m, big_num& m_prime,
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

  if (!big_mult(a, m_prime, t))
    return false;

  // reduce t mod 2^r
  int k = r / NBITSINUINT64;
  uint64_t u;

  for (i = (k + 1); i < t.capacity_; i++) t.value_[i] = 0ULL;
  int l = r - (k * NBITSINUINT64);
  u = (0xffffffffffffffffULL) >> (NBITSINUINT64 - l);
  t.value_[k] = t.value_[k] & u;
  t.normalize();

  if (!big_mult(t, m, w)) {
    return false;
  }
  if (!big_add(w, a, v)) {
    return false;
  }
  if (!big_shift(v, -r, mont_a)) {
    return false;
  }
  if (big_compare(m, mont_a) <= 0) {
    if (!big_unsigned_sub_from(mont_a, m)) {
      return false;
    }
  }
  if (big_compare(m, mont_a) <= 0) {
    // shouldn't need this
    big_mod_normalize(mont_a, m);
  }
  return true;
}

bool big_mont_mult(big_num& aR, big_num& bR, big_num& m, uint64_t r, big_num& m_prime,
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

  if (!big_unsigned_mult(aR, bR, t)) {
    ret = false;
  }
  if (ret && !big_mont_reduce(t, r, m, m_prime, abR)) {
    ret = false;
  }
  if (big_compare(abR, m) >= 0) {
    // shouldn't need this
    big_mod_normalize(abR, m);
  }
  return ret;
}

/*
 *  mont_exp
 *    Let mont_(a,b)= abR^-1 (mod p)
 *    R= b^r, m'= -m^(-1) (mod p), e= (e[t]...e[0])_2
 *    X= mont_(x, R^2(mod p))
 *    A= R (mod p)
 *    for(i=t; i>=0; i--) {
 *      A= mont_(A,A)
 *      if(e[i]==1) A= mont_(A,X)
 *    }
 *    A= mont_(A,1)
 *    return A
 */
bool big_mont_exp(big_num& b, big_num& e, int r, big_num& m, big_num& m_prime,
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
  int k = big_high_bit(e);
  int i;

  if (!big_make_mont(b, r, m, square)) {
    return false;
  }
  if (!big_make_mont(big_one, r, m, accum)) {
    return false;
  }
  for (i = 1; i <= k; i++) {
    if (big_bit_position_on(e, i)) {
      if (!big_mont_mult(accum, square, m, r, m_prime, t)) {
        return false;
      }
      accum.copy_from(t);
    }
    t.zero_num();
    if (i != k) {
      if (!big_mont_mult(square, square, m, r, m_prime, t)) {
        printf(
            "b.size_: %d, square.size_: %d, m.size_: %d, m_prime.size_: %d\n",
            b.size_, square.size_, m.size_, m_prime.size_);
        return false;
      }
      square.copy_from(t);
    }
  }
  return big_mont_reduce(accum, r, m, m_prime, out);
}
