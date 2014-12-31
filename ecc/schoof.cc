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
// 
// File: schoof.cc

#include "cryptotypes.h"
#include "bignum.h"
#include "ecc.h"
#include "indeterminate.h"
#include "ecc_symbolic.h"

// note that the real division polynomial, g_phi, is
//  g_phi[m]= g_phi2[m], if m is odd, and
//  g_phi[m]= (2y)g_phi2[m], if m is even.
//  From now on, the 2y is implicit during the calculation for even m
//  elsewhere, we assume a coefficient of y (not 2y) on
//  these so, at the end, we multiply through by 2


//  0. Precompute division polynomials
//  1. Pick S= {p[1], ..., p[k]: p[1]*p[2}*...*p[k]>4(p^(1/4)), p not in S
//  2. for p[1]=2, t=0 (2) iff (x^3+ax+b, x^p-x)= 1
//  3. for each odd l in S
//    3a.
//      p[l]= p (mod l), |p[l]|<l/2
//    3b.
//      Compute (x', y')= (x^(p^2), y^(p^2)) + p[l] (x,y)
//    3c. for j= 1,2,...(l-1)/2
//      3c(i).  Compute x[j], (x[j], y[j])= j(x,y)
//      3c(ii). If (x'-x[j]^p)= 0 (mod phi[l](x)), goto iii
//              If not, try next j; if all tried, goto 3d
//      3c(iii). Compute y' and y[j].  If (y'-y[j])/y= 0 (mod (phi[l](x))
//                                  then t= j (mod l), if not
//                                       t= -j (mod l)
//    3d. Let w^2= p (mod l).  If no such w, t=0 (mod l)
//    3e. If (gcd(numerator(x^p-x[w]), phi[l](x))= 1, t= 0 (mod l)
//          otherwise, compute (gcd(numerator(y^p-y[w]), phi[l](x))
//           if this is 1, t= 2w (mod l), otherwise, t= -2w (mod l)
//  4. User CRT to compute t, #E(p)= p+1-t, with t in right range for Hasse

//  In the symbolic computations, we assume P=(r(x), yq(x)) but that the
//  y is surpressed in the representation of the point as a polynomial
//  (r1(x), r2(x)).  r(x) and q(x) are ratio's of polynomials.
//  Our data type for these ratios is rationalpoly.
//  Surpressing the y in the representation of points saves us
//  from having to do multi-variate polynomial caclulations.
//  We have to be careful, however, in the calculations to
//  remember the implicit y.

bool ComputeCompositeSolutionUsingCrt(int n, uint64_t* moduli, uint64_t* solutions, 
                              BigNum& composite_modulus, BigNum& composite_solution) {
  int     i;
  BigNum  current_modulus(2);
  BigNum  current_solution(2);
  BigNum  new_composite_modulus(composite_solution.Capacity());
  BigNum  new_composite_solution(composite_solution.Capacity());

  if(n<=0)
    return false;

  composite_modulus.value_[0]= moduli[0];
  composite_solution.value_[0]= solutions[0];
  composite_modulus.Normalize();
  composite_solution.Normalize();

  for(i=1;i<n;i++) {
    current_modulus.value_[0]= moduli[i];
    current_solution.value_[0]= solutions[i];
    current_modulus.Normalize();
    current_solution.Normalize();
    if(!BigCRT(composite_solution, current_solution, composite_modulus, current_modulus, 
               new_composite_solution)) {
      printf("ComputeCompositeSolutionUsingCrt: BigCRT returns false\n");
      return false;
    }
    if(!BigUnsignedMult(composite_modulus, current_modulus, new_composite_modulus)) {
      printf("ComputeCompositeSolutionUsingCrt: BigUnsignedMult returns false\n");
      return false;
    }
    new_composite_solution.CopyTo(composite_solution);
    new_composite_modulus.CopyTo(composite_modulus);
  }
  return true;
}

// Division Polynomials
//  phi[0]= 0
//  phi[1]= 1
//  phi[2]= 2y
//  phi[3]= 3x^4+6ax^2+12bx-a^2
//  phi[4]= 4y(x^6+5ax^4+20bx^3-5a^2x^2-4abx-8b^2-a^3
//  phi[2m+1]= phi[m+2]phi^3[m]-phi[m-1]phi^3[m+1]
//  phi[2m]= phi[m]/phi[2](phi[m+2]phi^2[m-1]-phi[m-2]phi^2[m+1])
//  theta[m]= x phi^2[m]-phi[m+1]phi[m-1]
//  omega[m]= (phi[m]/(2 phi[2]) (phi[m+2] phi[m-1]-phi[m-2] phi^2[m+1])
int            Max_phi= -1;
Polynomial**   Phi_array= NULL;

bool InitPhi(int n) {
  return true;
}

void FreePhi() {
  int   j;

  if(Phi_array==NULL)
    return;
  for(j=0; j<Max_phi; j++) {
    if(Phi_array[j]!=NULL) {
      free(Phi_array[j]);
      Phi_array[j]= NULL;
    }
  }
}

// int BigCompare(BigNum& l, BigNum& r)
//   returns  1, if l>r
//   returns  0, if l==r
//   returns -1, if l<r

// floor(sqrt num) <= result < ceiling(sqrt num)
bool SquareRoot(BigNum& n, BigNum& r) {
  BigNum    top(r.Capacity());
  BigNum    bot(r.Capacity());
  BigNum    s(r.Capacity());
  BigNum    guess(r.Capacity());
  int       cmp;

  if(!BigUnsignedMult(n,n,s))
    return false;
  if(BigCompare(s, n)==0) {
    n.CopyTo(r);
    return true;
  }
  top.CopyFrom(n);
  if(BigCompare(Big_One, n)==0) {
    Big_One.CopyTo(r);
    return true;
  }
  bot.CopyFrom(Big_One);
  for(;;) {
    if(!BigUnsignedAdd(top, bot, s))
      return false;
    if(!BigShift(s, (int64_t)-1, guess))
      return false;
    if(!BigUnsignedMult(guess, guess, s))
      return false;
    cmp= BigCompare(s,n);
    if(cmp==0) {
      guess.CopyTo(r);
      return true;
    }
    if(cmp<0) {
      guess.CopyTo(bot);
    } else {
      guess.CopyTo(top);
    }
    if(!BigUnsignedAdd(Big_One, bot, s))
      return false;
    if(BigCompare(s, top)>=0) {
      bot.CopyTo(r);
      return true;
    }
  }
  return false;
}

bool PickPrimes(int* num_primes, uint64_t* prime_list, BigNum& p) {
  BigNum            composite_modulus(p.Capacity());
  BigNum            temp(p.Capacity());
  BigNum            current(1);
  BigNum            sqrt_sqrt_p(p.Capacity());
  BigNum            bound(p.Capacity());
  extern uint64_t   smallest_primes[];
  extern int        num_smallest_primes;

  prime_list[(*num_primes)++]= 2ULL;
  composite_modulus.value_[0]= 1ULL;
  composite_modulus.Normalize();
  if(!SquareRoot(p, temp))
    return false;
  if(!SquareRoot(temp, sqrt_sqrt_p))
    return false;
  if(!BigUnsignedMult(sqrt_sqrt_p, Big_Four, bound))
    return false;
  
  // prod_i prime_list[i]> 4p^(1/4)
  for(;;) {
    if(BigCompare(composite_modulus, bound)>0)
      break;
    prime_list[*num_primes]= smallest_primes[*num_primes];
    current.value_[0]= smallest_primes[*num_primes];
    current.Normalize();
    if(!BigUnsignedMult(composite_modulus, current, temp))
      return false;
    (*num_primes)++;
    temp.CopyTo(composite_modulus);
  }
  return true;
}

bool Compute_t_mod_2(Polynomial& curve_poly, uint64_t* result) {
  //  t=0 iff (x^3+ax+b, x^p-x)= 1
  return true;
}

bool Compute_t_mod_l(Polynomial& curve_poly, uint64_t l, uint64_t* result) {
//  p_reduced[l]= p (mod l), |p_reduced[l]|<l/2
//  Compute (x', y')= (x^(p^2), y^(p^2)) + p_reduced(x,y)
//  for j= 1,2,...(l-1)/2
//      Compute x[j], (x[j], y[j])= j(x,y)
//      if (x'-x[j]^p)!= 0 (mod phi[l](x))
//        continue;
//      Compute y' and y[j].  
//      if (y'-y[j])/y== 0 (mod (phi[l](x)) 
//         t= j (mod l)
//      else
//         t= -j (mod l)
//  
//  if p is not a residue mod l
//      t=0 (mod l); return;
//  w^2= p (mod l).  
//  if(gcd(numerator(x^p-x[w]), phi[l](x))==1
//    t= 0 (mod l); return
//  test=(gcd(numerator(y^p-y[w]), phi[l](x))
//  if(test==1)
//    t= 2w (mod l); return;
//  else
//    t= -2w (mod l) return;
  int   n= (l-1)/2;
  int   j;

  for(j=1; j<=n; j++) {
  }
  return true;
}

//  schoof
//   Given short Weierstrauss curves, compute
//   the order of the elliptic curve group.
bool schoof(EccCurve& curve, BigNum& order) {
  int       num_primes= 0;
  uint64_t  primes[512];
  uint64_t  t_mod_prime[512];
  BigNum    composite_modulus(order.Capacity());
  BigNum    composite_solution(order.Capacity());
  BigNum    s(order.Capacity());
  Polynomial  curve_poly(curve.p_->Capacity(), 5, *curve.p_);
  int       j;

  if(!PickPrimes(&num_primes, primes, *curve.p_))
    return false;
  if(!PolyFromCurve(curve, curve_poly))
    return false;
  if(!InitPhi((int) primes[num_primes-1]))
    return false;
  bool  ret= true;

  // compute answers modulo primes
  if(!Compute_t_mod_2(curve_poly, &t_mod_prime[0])) {
    ret= false;
    goto done;
  }
  for(j=1;j<num_primes;j++) {
    if(!Compute_t_mod_l(curve_poly, primes[j], &t_mod_prime[j])) {
      ret= false;
      goto done;
    }
  }
  // compute t using CRT
  if(!ComputeCompositeSolutionUsingCrt(num_primes, primes, t_mod_prime,
                              composite_modulus, composite_solution)) {
    ret= false;
    goto done;
  }
  // get #E = p+1-t
  order.ZeroNum();
  if(!BigUnsignedAdd(*curve.p_, Big_One, s)) {
    ret= false;
    goto done;
  }
  if(!BigSub(s, composite_solution, order)) {
    ret= false;
    goto done;
  }
done:
  FreePhi();
  return ret;
}
