//
//  File: bsgs.cc
//  Description: Baby step, giant step point counting in ECC
//
//  Copyright (c) 2014, John Manferdelli.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

#include "bignum.h"
#include "stdio.h"
#include "cryptotypes.h"
#include "bignum.h"
#include "ecc.h"

extern bool SquareRoot(BigNum& n, BigNum& r);

// ----------------------------------------------------------------------------

/*
 * 1. Q= (q+1)P
 * 2. Choose m>q^(1/4)
 * 3. Compute jP, j= 0, 1, ..., m and store
 * 4. Compute Q+k(2mP), k= -m, -m+1, ... 0, 1, ..., m
 *      until Q+k(2mP)= jP or -jP
 * 5. (q+1+2mk+j)P= O or (q+1+2mk-j)P= O.  Let M be coefficient of P
 * 6. Factor M into p[0]^e[0] ... p[l]^e[l]
 * 7. Repeat until failure if (M/p[i])P=0, replace M with /p[i]
 * 8. Conclude |P|= M
 * If we're looking for the order of the group, do the above with
 *    random points until LCM divides one N with q+1-2(q^1/2)<=N<=q+1+2(q^1/2).
 *    Conclude N is the order
 */

int64_t Num_points_in_table = -1;
CurvePoint** Points_table = nullptr;

int64_t Index_point_in_table(CurvePoint& P) {
  int64_t j;

  for (j = 0; j < Num_points_in_table; j++) {
    if (BigCompare(*Points_table[j]->x_, *P.x_) != 0) continue;
    if (BigCompare(*Points_table[j]->y_, *P.y_) == 0) return j;
  }
  return -1LL;
}

bool Populate_table(EccCurve& curve, int64_t m, CurvePoint& P) {
  int64_t j;
  BigNum j_bignum(2);

  Points_table = new CurvePoint* [m];
  for (j = 0; j <= m; j++) {
    j_bignum.value_[0] = (uint64_t)j;
    j_bignum.Normalize();
    Points_table[j] = new CurvePoint(curve.p_->Capacity());
    if (!EccMult(curve, P, j_bignum, *Points_table[j])) return false;
  }
  Num_points_in_table = m + 1;
  return true;
}

void Print_table() {
  int64_t j;

  printf("%lld points in point table\n", Num_points_in_table);
  if (Num_points_in_table <= 0) return;
  for (j = 0; j < Num_points_in_table; j++) {
    if (Points_table[j] != nullptr) {
      printf("%lld: ", j);
      Points_table[j]->PrintPoint();
      printf("\n");
    }
  }
}

void Free_table() {
  int64_t j;

  if (Num_points_in_table <= 0) return;
  for (j = 0; j < Num_points_in_table; j++) {
    if (Points_table[j] != nullptr) free(Points_table[j]);
    Points_table[j] = nullptr;
  }
}

bool Reduce_annihilator(EccCurve& curve, CurvePoint& P, uint64_t n,
                        BigNum& order) {
  extern uint64_t smallest_primes[];
  extern int num_smallest_primes;
  int j;
  BigNum t_bignum(2);
  CurvePoint Q(2);

  for (j = 0; j < num_smallest_primes && n >= smallest_primes[j]; j++) {
    while ((n % smallest_primes[j]) == 0 && n > 1ULL) {
      t_bignum.value_[0] = n / smallest_primes[j];
      t_bignum.Normalize();
      if (!EccMult(curve, P, t_bignum, Q)) return false;
      if (!Q.IsZero()) break;
      n /= smallest_primes[j];
    }
  }
  order.value_[0] = n;
  order.Normalize();
  return true;
}

bool eccbsgspointorder(EccCurve& curve, CurvePoint& P, BigNum& order) {
  BigNum sqrt_p(curve.p_->Capacity() + 1);
  BigNum sqrt_sqrt_p(curve.p_->Capacity() + 1);
  BigNum p_plus_1(curve.p_->Capacity());
  BigNum two_m(curve.p_->Capacity() + 1);
  BigNum k_bignum(curve.p_->Capacity() + 1);
  BigNum j_bignum(curve.p_->Capacity() + 1);
  BigNum n_bignum(curve.p_->Capacity() + 1);
  BigNum n1(curve.p_->Capacity() + 1);
  BigNum n2(curve.p_->Capacity() + 1);
  BigNum n3(curve.p_->Capacity() + 1);
  BigNum n4(curve.p_->Capacity() + 1);
  CurvePoint two_m_P(curve.p_->Capacity() + 1);
  CurvePoint Q(curve.p_->Capacity() + 1);
  CurvePoint R(curve.p_->Capacity() + 1);
  CurvePoint T(curve.p_->Capacity() + 1);
  int64_t m;
  int64_t j, k;
  uint64_t n = 0ULL;
  bool ret = false;

  if (!SquareRoot(*curve.p_, sqrt_p)) return false;
  if (!SquareRoot(sqrt_p, sqrt_sqrt_p)) return false;
  if (!BigUnsignedAdd(*curve.p_, Big_One, p_plus_1)) return false;
  if (!EccMult(curve, P, p_plus_1, Q)) return false;
  if (sqrt_sqrt_p.Size() > 1) {
    printf("BSGS limited to p^(1/4)<2^64\n");
    return false;
  }
  m = sqrt_sqrt_p.value_[0] + 1ULL;
  if (!Populate_table(curve, m, P)) {
    printf("Can't Populate_table\n");
    return false;
  }
  BigNum m_bignum(2, (uint64_t)m);
  if (!BigUnsignedMult(m_bignum, Big_Two, two_m)) goto done;

  if (!EccMult(curve, P, two_m, two_m_P)) {
    goto done;
  }

  for (k = -m; k <= m; k++) {
    // Compute R= Q+k(2mP)
    if (k < 0) {
      k_bignum.value_[0] = (uint64_t)-k;
      k_bignum.ToggleSign();
    } else {
      k_bignum.value_[0] = (uint64_t)k;
    }
    k_bignum.Normalize();
    if (!EccMult(curve, two_m_P, k_bignum, T)) goto done;
    if (!EccAdd(curve, Q, T, R)) goto done;

    // In table?
    j = Index_point_in_table(R);
    if (j < 0) continue;

    // Compute n= (p+1+2mk+-j)
    j_bignum.value_[0] = (uint64_t)j;
    j_bignum.Normalize();
    if (!BigUnsignedMult(m_bignum, Big_Two, n2)) goto done;
    if (!BigUnsignedMult(k_bignum, n2, n3)) goto done;
    if (!BigAdd(n3, p_plus_1, n4)) goto done;
    if (!BigAdd(n4, j_bignum, n_bignum)) goto done;
    if (!EccMult(curve, P, n_bignum, T)) goto done;
    if (T.IsZero()) {
      n = n_bignum.value_[0];
      if (Reduce_annihilator(curve, P, n, order)) {
        ret = true;
        goto done;
      }
    }
    j_bignum.ToggleSign();
    if (!BigAdd(n4, j_bignum, n_bignum)) goto done;
    if (!EccMult(curve, P, n_bignum, T)) goto done;
    if (T.IsZero()) {
      n = n_bignum.value_[0];
      if (Reduce_annihilator(curve, P, n, order)) {
        ret = true;
        goto done;
      }
    }
    goto done;
  }

done:
  Free_table();
  return ret;
}

// ----------------------------------------------------------------------------
