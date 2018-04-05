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
// File: ecc.cc

#include "cryptotypes.h"
#include "bignum.h"
#include "ecc.h"
#include "keys.h"
#include "keys.pb.h"
#include "intel64_arith.h"
#include "conversions.h"
#define FASTECCMULT

EccKey P256_Key;
bool P256_key_valid = false;

CurvePoint::CurvePoint() {
  x_ = nullptr;
  y_ = nullptr;
  z_ = nullptr;
}

CurvePoint::CurvePoint(int size) {
  x_ = new BigNum(size);
  y_ = new BigNum(size);
  z_ = new BigNum(size);
  z_->value_[0] = 1ULL;
  z_->Normalize();
}

CurvePoint::CurvePoint(BigNum& x, BigNum& y) {
  x_ = new BigNum(x.capacity_);
  x_->CopyFrom(x);
  y_ = new BigNum(y.capacity_);
  y_->CopyFrom(y);
  z_ = new BigNum(x.capacity_);
  z_->value_[0] = 1ULL;
  z_->Normalize();
}

CurvePoint::~CurvePoint() {
  Clear();
  if (x_ != nullptr) {
    x_->ZeroNum();
    delete x_;
    x_ = nullptr;
  }
  if (y_ != nullptr) {
    y_->ZeroNum();
    delete y_;
    y_ = nullptr;
  }
  if (z_ != nullptr) {
    z_->ZeroNum();
    delete z_;
    z_ = nullptr;
  }
}

bool CurvePoint::IsZero() {
  return x_->IsZero() && z_->IsZero() && y_->IsOne();
}

void CurvePoint::MakeZero() {
  x_->ZeroNum();
  y_->CopyFrom(Big_One);
  z_->ZeroNum();
}

bool CurvePoint::CopyFrom(CurvePoint& P) {
  x_->CopyFrom(*P.x_);
  y_->CopyFrom(*P.y_);
  z_->CopyFrom(*P.z_);
  return true;
}

bool CurvePoint::CopyTo(CurvePoint& P) {
  x_->CopyTo(*P.x_);
  y_->CopyTo(*P.y_);
  z_->CopyTo(*P.z_);
  return true;
}

CurvePoint::CurvePoint(CurvePoint& P) {
  x_ = new BigNum(P.x_->capacity_);
  x_->CopyFrom(*P.x_);
  y_ = new BigNum(P.y_->capacity_);
  y_->CopyFrom(*P.y_);
  z_ = new BigNum(P.z_->capacity_);
  z_->CopyFrom(*P.z_);
}

CurvePoint::CurvePoint(CurvePoint& P, int capacity) {
  x_ = new BigNum(capacity);
  x_->CopyFrom(*P.x_);
  y_ = new BigNum(capacity);
  y_->CopyFrom(*P.y_);
  z_ = new BigNum(capacity);
  z_->CopyFrom(*P.z_);
}

void CurvePoint::Clear() {
  if (x_ != nullptr) x_->ZeroNum();
  if (y_ != nullptr) y_->ZeroNum();
  if (x_ != nullptr) z_->ZeroNum();
}

bool CurvePoint::Normalize(BigNum& p) {
  // TODO
  if (z_->IsZero() || z_->IsOne()) return true;
  return false;
}

void CurvePoint::PrintPoint() {
  if (x_ != nullptr) {
    printf("[");
    PrintNumToConsole(*x_, 10ULL);
    printf(", ");
    PrintNumToConsole(*y_, 10ULL);
    printf(", ");
    PrintNumToConsole(*z_, 10ULL);
    printf("]");
  }
}

EccCurve::EccCurve() {
  a_ = nullptr;
  b_ = nullptr;
  p_ = nullptr;
}

EccCurve::EccCurve(int size) {
  a_ = new BigNum(size);
  b_ = new BigNum(size);
  p_ = new BigNum(size);
}

EccCurve::EccCurve(BigNum& a, BigNum& b, BigNum& p) {
  a_ = new BigNum(a.capacity_);
  a_->CopyFrom(a);
  b_ = new BigNum(b.capacity_);
  b_->CopyFrom(b);
  p_ = new BigNum(p.capacity_);
  p_->CopyFrom(p);
}

EccCurve::~EccCurve() {
  Clear();
  if (a_ != nullptr) {
    a_->ZeroNum();
    delete a_;
    a_ = nullptr;
  }
  if (b_ != nullptr) {
    b_->ZeroNum();
    delete b_;
    b_ = nullptr;
  }
  if (p_ != nullptr) {
    p_->ZeroNum();
    delete p_;
    p_ = nullptr;
  }
}

void EccCurve::Clear() {
  if (a_ != nullptr) a_->ZeroNum();
  if (b_ != nullptr) b_->ZeroNum();
  if (p_ != nullptr) p_->ZeroNum();
}

void EccCurve::PrintCurve() {
  if (a_ != nullptr) {
    printf("Curve: y^2= x^3 + ");
    PrintNumToConsole(*a_, 10ULL);
    printf(" x + ");
    PrintNumToConsole(*b_, 10ULL);
    printf(" (mod ");
    PrintNumToConsole(*p_, 10ULL);
    printf(")\n");
  }
}

// Disc= -(4a^3+27b^2) (mod p)

/*
 *  Pick parameter k.
 *  x= m<<shift+j
 *  for the first j: x^3+ax+b (mod p) is has a square root, y
 *  Point is (x,y)
 */
bool EccEmbed(EccCurve& c, BigNum& m, CurvePoint& P, int shift, int trys) {
  BigNum m_x(2 * c.p_->capacity_);
  BigNum t1(2 * c.p_->capacity_);
  BigNum t2(2 * c.p_->capacity_);
  BigNum t3(2 * c.p_->capacity_);
  int i;

  if (!BigShift(m, shift, m_x)) {
    LOG(ERROR) << "BigShift failed in EccEmbed\n";
    return false;
  }
  if (BigCompare(*c.p_, m_x) <= 0) {
    LOG(ERROR) << "BigCompare failed in EccEmbed\n";
    return false;
  }
  for (i = 0; i < trys; i++) {
    if (!BigModMult(m_x, m_x, *c.p_, t1)) {
      LOG(ERROR) << "BigModMult failed in EccEmbed\n";
      return false;
    }
    if (!BigModMult(m_x, t1, *c.p_, t2)) {
      LOG(ERROR) << "BigModMult failed in EccEmbed\n";
      return false;
    }
    t1.ZeroNum();
    if (!BigModMult(m_x, *c.a_, *c.p_, t1)) {
      LOG(ERROR) << "BigModMult failed in EccEmbed\n";
      return false;
    }
    if (!BigModAdd(t1, t2, *c.p_, t3)) {
      LOG(ERROR) << "BigModAdd failed in EccEmbed\n";
      return false;
    }
    t1.ZeroNum();
    t2.ZeroNum();
    if (!BigModAdd(t3, *c.b_, *c.p_, t1)) {
      LOG(ERROR) << "BigModAdd failed in EccEmbed\n";
      return false;
    }
    if (BigModIsSquare(t1, *c.p_)) {
      if (!BigModSquareRoot(t1, *c.p_, *P.y_)) {
        LOG(ERROR) << "BigModSquareRoot failed in EccEmbed\n";
        return false;
      }
      P.x_->CopyFrom(m_x);
      P.z_->ZeroNum();
      P.z_->value_[0] = 1ULL;
      break;
    }
    if (!BigUnsignedAddTo(m_x, Big_One)) {
      LOG(ERROR) << "BigUnsignedAddTo failed in EccEmbed\n";
      return false;
    }
  }
  if (i >= trys) {
    LOG(ERROR) << "Too many tries EccEmbed\n";
    return false;
  }
  return true;
}

bool EccExtract(EccCurve& c, CurvePoint& P, BigNum& m, int shift) {
  BigNum t1(2 * c.p_->capacity_);
  BigNum t2(2 * c.p_->capacity_);
  BigNum t3(2 * c.p_->capacity_);

  m.ZeroNum();
  if (!BigModMult(*P.x_, *P.x_, *c.p_, t1)) {
    LOG(ERROR) << "BigModMult failed in EccExtract\n";
    return false;
  }
  if (!BigModMult(*P.x_, t1, *c.p_, t2)) {
    LOG(ERROR) << "BigModMult failed in EccExtract\n";
    return false;
  }
  t1.ZeroNum();
  if (!BigModMult(*P.x_, *c.a_, *c.p_, t1)) {
    LOG(ERROR) << "BigModMult failed in EccExtract\n";
    return false;
  }
  if (!BigModAdd(t1, t2, *c.p_, t3)) {
    LOG(ERROR) << "BigModAdd failed in EccExtract\n";
    return false;
  }
  t2.ZeroNum();
  if (!BigModAdd(t3, *c.b_, *c.p_, t2)) {
    LOG(ERROR) << "BigModAdd failed in EccExtract\n";
    return false;
  }
  t1.ZeroNum();
  if (!BigModMult(*P.y_, *P.y_, *c.p_, t1)) {
    LOG(ERROR) << "BigModMult failed in EccExtract\n";
    return false;
  }
  if (BigCompare(t1, t2) != 0) {
    printf("Extract compare error:\n");
    printf("P:\n");
    P.PrintPoint();
    printf("\n");
    printf("t1: ");
    PrintNumToConsole(t1, 10ULL);
    printf("\n");
    printf("t2: ");
    PrintNumToConsole(t2, 10ULL);
    printf("\n");
    LOG(ERROR) << "BigCompare failed in EccExtract\n";
    return false;
  }
  if (!BigShift(*P.x_, -shift, m)) {
    LOG(ERROR) << "BigShift failed in EccExtract\n";
    return false;
  }
  return true;
}

/*
 *  y^2= x^3+ax+b (mod p)
 *  P=(x1, y1) and Q=(x2, y2).  Want P+Q=R=(x3,y3).
 *  if P= O, R=Q.
 *  if Q= O, R=P.
 *  if x1=x2 and y1=-y2, R= O
 *  if x1=x2 and y1+y2!=0, m= (3a1^2+a)/(y1+y2) otherwise
 *    m= (y2-y1)/(x2-x1)
 *    x3= m^2-x1-x2, y3= m(x1-x3)-y1
 */
bool EccAdd(EccCurve& c, CurvePoint& P, CurvePoint& Q, CurvePoint& R) {
  P.Normalize(*c.p_);
  Q.Normalize(*c.p_);

  if (P.IsZero()) {
    return Q.CopyTo(R);
  }
  if (Q.IsZero()) {
    return P.CopyTo(R);
  }
  BigNum m(2 * c.p_->size_);
  BigNum t1(2 * c.p_->size_);
  BigNum t2(2 * c.p_->size_);
  BigNum t3(2 * c.p_->size_);

  R.z_->CopyFrom(Big_One);
  if (BigCompare(*P.x_, *Q.x_) != 0) {
    if (!BigModSub(*Q.x_, *P.x_, *c.p_, t1)) {
      return false;
    }
    if (!BigModSub(*Q.y_, *P.y_, *c.p_, t2)) {
      return false;
    }
    if (!BigModDiv(t2, t1, *c.p_, m)) {
      return false;
    }
  } else {
    if (!BigModAdd(*P.y_, *Q.y_, *c.p_, t1)) {
      return false;
    }
    if (t1.IsZero()) {
      R.MakeZero();
      return true;
    }
    if (!BigModMult(*P.x_, *P.x_, *c.p_, t3)) {
      return false;
    }
    if (!BigModMult(Big_Three, t3, *c.p_, t2)) {
      return false;
    }
    t3.ZeroNum();
    if (!BigModAdd(t2, *c.a_, *c.p_, t3)) {
      return false;
    }
    if (!BigModDiv(t3, t1, *c.p_, m)) {
      return false;
    }
  }
  t1.ZeroNum();
  t2.ZeroNum();
  if (!BigModMult(m, m, *c.p_, t1)) {
    return false;
  }
  if (!BigModSub(t1, *P.x_, *c.p_, t2)) {
    return false;
  }
  if (!BigModSub(t2, *Q.x_, *c.p_, *R.x_)) {
    return false;
  }
  t1.ZeroNum();
  t2.ZeroNum();
  t3.ZeroNum();
  if (!BigModSub(*P.x_, *R.x_, *c.p_, t1)) {
    return false;
  }
  if (!BigModMult(m, t1, *c.p_, t2)) {
    return false;
  }
  if (!BigModSub(t2, *P.y_, *c.p_, *R.y_)) {
    return false;
  }
  return true;
}

bool EccSub(EccCurve& c, CurvePoint& P, CurvePoint& Q, CurvePoint& R) {
  if (Q.IsZero()) {
    R.CopyFrom(P);
    return true;
  }

  CurvePoint minus_Q(Q);
  BigNum t(2 * c.p_->capacity_);
  if (!BigSub(*c.p_, *Q.y_, t)) {
    return false;
  }
  if (!BigModNormalize(t, *c.p_)) {
    return false;
  }
  minus_Q.y_->CopyFrom(t);
  return EccAdd(c, P, minus_Q, R);
}

bool EccDouble(EccCurve& c, CurvePoint& P, CurvePoint& R) {
  return EccAdd(c, P, P, R);
}

//  For Jacobian projective coordinates, see hyperellitptic.org

//  From Cohen, Miyaka, Ono
//  Projective Addition
//    y^2z=x^3+axz^2+bz^3
//    P != +- Q
//    u= y2z1-y1z2, v=x2z1-x1z2, A= u^2z1z2-v^3-2v^2x1z2
//    x3= vA, y3= u(v^2x1z2-A)-v^3y1z2, z3= v^3z1z2
//    A=u^2z[1]z[2]-v^3-2v^2x[1]z[2]
//  Doubling
//    R= 2P
//    x3=2hs, y3= w(4B-h) -8y[1]^2s^2, z3= 8s^3
//    w=az1^2+3x1^2, s=y1z1, B= x1y1s, h= w^2-8B
//

bool ProjectiveToAffine(EccCurve& c, CurvePoint& P) {
  BigNum x(1 + 2 * c.p_->size_);
  BigNum y(1 + 2 * c.p_->size_);
  BigNum zinv(1 + 2 * c.p_->size_);

  if (P.z_->IsZero()) {
    P.MakeZero();
    return true;
  }
  if (P.z_->IsOne()) return true;
  if (!BigModInv(*P.z_, *c.p_, zinv)) {
    LOG(ERROR) << "ProjectiveToAffine can't BigModInv\n";
    return false;
  }
  if (!BigModMult(*P.x_, zinv, *c.p_, x)) {
    LOG(ERROR) << "ProjectiveToAffine BigModMult(2) failed\n";
    return false;
  }
  if (!BigModMult(*P.y_, zinv, *c.p_, y)) {
    LOG(ERROR) << "ProjectiveToAffine BigModMult(3) failed\n";
    return false;
  }
  P.x_->CopyFrom(x);
  P.y_->CopyFrom(y);
  P.z_->CopyFrom(Big_One);
  return true;
}

bool ProjectiveAdd(EccCurve& c, CurvePoint& P, CurvePoint& Q, CurvePoint& R) {
  BigNum u(1 + 2 * c.p_->size_);
  BigNum v(1 + 2 * c.p_->size_);
  BigNum A(1 + 2 * c.p_->size_);
  BigNum u_squared(1 + 2 * c.p_->size_);
  BigNum v_squared(1 + 2 * c.p_->size_);
  BigNum w(1 + 2 * c.p_->size_);
  BigNum t(1 + 2 * c.p_->size_);
  BigNum t1(1 + 2 * c.p_->size_);
  BigNum t2(1 + 2 * c.p_->size_);
  BigNum t3(1 + 2 * c.p_->size_);
  BigNum t4(1 + 2 * c.p_->size_);
  BigNum a1(1 + 2 * c.p_->size_);
  BigNum a2(1 + 2 * c.p_->size_);
  BigNum b1(1 + 2 * c.p_->size_);
  BigNum b2(1 + 2 * c.p_->size_);

  // If P=O, Q
  if (P.z_->IsZero()) {
    R.CopyFrom(Q);
    return true;
  }
  // If Q=O, P
  if (Q.z_->IsZero()) {
    R.CopyFrom(P);
    return true;
  }
  if (!BigModMult(*P.x_, *Q.z_, *c.p_, a1)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(*P.y_, *Q.z_, *c.p_, a2)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(*Q.x_, *P.z_, *c.p_, b1)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(*Q.y_, *P.z_, *c.p_, b2)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }

  // If P= Q, use doubling
  if (BigCompare(a1, b1) == 0) {
    if (BigCompare(a2, b2) == 0) return ProjectiveDouble(c, P, R);
    if (!BigModAdd(a2, b2, *c.p_, t)) {
      LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
      return false;
    }
    if (t.IsZero()) {
      R.MakeZero();
      return true;
    }
  }

  // u= y2z1-y1z2
  if (!BigModMult(*Q.y_, *P.z_, *c.p_, t)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(*P.y_, *Q.z_, *c.p_, w)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModSub(t, w, *c.p_, u)) {
    LOG(ERROR) << "ProjectiveAdd BigModSub(x) failed\n";
    return false;
  }
  // v=x2z1-x1z2
  if (!BigModMult(*Q.x_, *P.z_, *c.p_, t)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(*P.x_, *Q.z_, *c.p_, w)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModSub(t, w, *c.p_, v)) {
    LOG(ERROR) << "ProjectiveAdd BigModSub(x) failed\n";
    return false;
  }
  // A= u^2z1z2-v^3-2v^2x1z2
  if (!BigModMult(u, u, *c.p_, u_squared)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(v, v, *c.p_, v_squared)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(u_squared, *P.z_, *c.p_, t)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(t, *Q.z_, *c.p_, t1)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(v_squared, v, *c.p_, t2)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(v_squared, *P.x_, *c.p_, t)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(t, *Q.z_, *c.p_, t4)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigShift(t4, 1, t3)) {
    LOG(ERROR) << "ProjectiveAdd BigShift(x) failed\n";
    return false;
  }
  BigModNormalize(t3, *c.p_);
  t.ZeroNum();
  if (!BigModSub(t1, t2, *c.p_, t)) {
    LOG(ERROR) << "ProjectiveAdd BigModSub(x) failed\n";
    return false;
  }
  if (!BigModSub(t, t3, *c.p_, A)) {
    LOG(ERROR) << "ProjectiveAdd BigModSub(x) failed\n";
    return false;
  }
  // x3= vA
  if (!BigModMult(v, A, *c.p_, *R.x_)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  // z3= v^3z1z2
  if (!BigModMult(*P.z_, *Q.z_, *c.p_, t)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(t, t2, *c.p_, *R.z_)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  // y3= u(v^2x1z2-A)-v^3y1z2
  t.ZeroNum();
  if (!BigModSub(t4, A, *c.p_, t)) {
    LOG(ERROR) << "ProjectiveAdd BigModSub(x) failed\n";
    return false;
  }
  if (!BigModMult(t, u, *c.p_, w)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(t2, *P.y_, *c.p_, t)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(t, *Q.z_, *c.p_, t4)) {
    LOG(ERROR) << "ProjectiveAdd BigModMult(x) failed\n";
    return false;
  }
  if (!BigModSub(w, t4, *c.p_, *R.y_)) {
    LOG(ERROR) << "ProjectiveAdd BigModSub(x) failed\n";
    return false;
  }
  return true;
}

bool ProjectiveDouble(EccCurve& c, CurvePoint& P, CurvePoint& R) {
  BigNum w(1 + 2 * c.p_->size_);
  BigNum w_squared(1 + 2 * c.p_->size_);
  BigNum s(1 + 2 * c.p_->size_);
  BigNum s_squared(1 + 2 * c.p_->size_);
  BigNum h(1 + 2 * c.p_->size_);
  BigNum B(1 + 2 * c.p_->size_);
  BigNum t1(1 + 2 * c.p_->size_);
  BigNum t2(1 + 2 * c.p_->size_);
  BigNum t3(1 + 2 * c.p_->size_);
  BigNum z1_squared(1 + 2 * c.p_->size_);
  BigNum x1_squared(1 + 2 * c.p_->size_);
  BigNum y1_squared(1 + 2 * c.p_->size_);

  // w=az1^2+3x1^2
  if (!BigModMult(*P.z_, *P.z_, *c.p_, z1_squared)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(*P.x_, *P.x_, *c.p_, x1_squared)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(*c.a_, z1_squared, *c.p_, t1)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(Big_Three, x1_squared, *c.p_, t2)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  if (!BigModAdd(t1, t2, *c.p_, w)) {
    LOG(ERROR) << "ProjectiveDouble BigModAdd(x) failed\n";
    return false;
  }
  // s=y1z1
  if (!BigModMult(*P.y_, *P.z_, *c.p_, s)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  // B= x1y1s
  if (!BigModMult(*P.x_, *P.y_, *c.p_, t1)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(s, t1, *c.p_, B)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  // h= w^2-8B
  if (!BigModMult(w, w, *c.p_, w_squared)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  t1.ZeroNum();
  if (!BigShift(B, 3, t1)) {
    LOG(ERROR) << "ProjectiveDouble Bigshift(x) failed\n";
    return false;
  }
  BigModNormalize(t1, *c.p_);
  if (!BigModSub(w_squared, t1, *c.p_, h)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }

  // x3=2hs
  t1.ZeroNum();
  if (!BigModMult(h, s, *c.p_, t1)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  t2.ZeroNum();
  if (!BigShift(t1, 1, t2)) {
    LOG(ERROR) << "ProjectiveDouble Bigshift(x) failed\n";
    return false;
  }
  BigModNormalize(t2, *c.p_);
  R.x_->CopyFrom(t2);

  // z3= 8s^3
  if (!BigModMult(s, s, *c.p_, s_squared)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(s_squared, s, *c.p_, t1)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  t2.ZeroNum();
  if (!BigShift(t1, 3, t2)) {
    LOG(ERROR) << "ProjectiveDouble Bigshift(x) failed\n";
    return false;
  }
  BigModNormalize(t2, *c.p_);
  R.z_->CopyFrom(t2);

  // y3= w(4B-h) -8y1^2s^2
  if (!BigModMult(*P.y_, *P.y_, *c.p_, y1_squared)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  t1.ZeroNum();
  t2.ZeroNum();
  if (!BigShift(B, 2, t1)) {
    LOG(ERROR) << "ProjectiveDouble Bigshift(x) failed\n";
    return false;
  }
  BigModNormalize(t1, *c.p_);
  if (!BigModSub(t1, h, *c.p_, t2)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  t1.ZeroNum();
  if (!BigModMult(w, t2, *c.p_, t1)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  if (!BigModMult(s_squared, y1_squared, *c.p_, t2)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  if (!BigShift(t2, 3, t3)) {
    LOG(ERROR) << "ProjectiveDouble Bigshift(x) failed\n";
    return false;
  }
  BigModNormalize(t3, *c.p_);
  if (!BigModSub(t1, t3, *c.p_, *R.y_)) {
    LOG(ERROR) << "ProjectiveDouble BigModMult(x) failed\n";
    return false;
  }
  return true;
}

bool ProjectivePointMult(EccCurve& c, BigNum& x, CurvePoint& P, CurvePoint& R) {
  if (x.IsZero()) {
    R.MakeZero();
    return true;
  }
  if (x.IsOne()) {
    return R.CopyFrom(P);
  }
  if (P.z_->IsZero()) {
    R.MakeZero();
    return true;
  }

  int k = BigHighBit(x);
  int i;
  CurvePoint double_point(P, 1 + 2 * c.p_->capacity_);
  CurvePoint accum_point(1 + 2 * c.p_->capacity_);
  CurvePoint t1(1 + 2 * c.p_->capacity_);

  accum_point.MakeZero();
  for (i = 1; i < k; i++) {
    if (BigBitPositionOn(x, i)) {
      ProjectiveAdd(c, accum_point, double_point, t1);
      t1.CopyTo(accum_point);
      t1.MakeZero();
    }
    if (!ProjectiveDouble(c, double_point, t1)) {
      return false;
    }
    t1.CopyTo(double_point);
    t1.MakeZero();
  }
  if (BigBitPositionOn(x, i)) {
    ProjectiveAdd(c, accum_point, double_point, t1);
    t1.CopyTo(accum_point);
    t1.MakeZero();
  }

  accum_point.CopyTo(R);
  if (x.IsNegative()) {
    R.y_->ToggleSign();
  }
  return true;
}

bool EccMult(EccCurve& c, CurvePoint& P, BigNum& x, CurvePoint& R) {
  if (x.IsZero()) {
    R.MakeZero();
    return true;
  }
  if (x.IsOne()) {
    return R.CopyFrom(P);
  }
  int k = BigHighBit(x);
  int i;
  CurvePoint double_point(P, 1 + 2 * c.p_->capacity_);
  CurvePoint accum_point(1 + 2 * c.p_->capacity_);
  CurvePoint t1(1 + 2 * c.p_->capacity_);

  accum_point.MakeZero();
  for (i = 1; i < k; i++) {
    if (BigBitPositionOn(x, i)) {
      EccAdd(c, accum_point, double_point, t1);
      t1.CopyTo(accum_point);
      t1.MakeZero();
    }
    if (!EccDouble(c, double_point, t1)) {
      return false;
    }
    t1.CopyTo(double_point);
    t1.MakeZero();
  }
  if (BigBitPositionOn(x, i)) {
    EccAdd(c, accum_point, double_point, t1);
    t1.CopyTo(accum_point);
    t1.MakeZero();
  }
  accum_point.CopyTo(R);
  if (x.IsNegative()) {
    R.y_->ToggleSign();
  }
  return true;
}

bool FasterEccMult(EccCurve& c, CurvePoint& P, BigNum& x, CurvePoint& R) {
  if (x.IsZero()) {
    R.MakeZero();
    return true;
  }
  if (x.IsOne()) {
    return R.CopyFrom(P);
  }
  if (!ProjectivePointMult(c, x, P, R)) {
    LOG(ERROR) << "ProjectivePointMult failed\n";
    return false;
  }
  if (!ProjectiveToAffine(c, R)) {
    LOG(ERROR) << "ProjectiveToAffine failed\n";
    return false;
  }
  if (x.IsNegative()) {
    R.y_->ToggleSign();
  }
  return true;
}

EccKey::EccKey() {
  bit_size_modulus_ = 0;
  a_ = nullptr;
  order_of_g_ = nullptr;
}

EccKey::~EccKey() {
  if (a_ != nullptr) {
    a_->ZeroNum();
    delete a_;
  }
  if (order_of_g_ != nullptr) {
    order_of_g_->ZeroNum();
    delete order_of_g_;
  }
  c_.Clear();
  g_.Clear();
  base_.Clear();
}

bool EccKey::MakeEccKey(const char* name, const char* usage, const char* owner,
                        int num_bits, double secondstolive, EccCurve* c,
                        CurvePoint* g, CurvePoint* base, BigNum* order, BigNum* secret) {
  bit_size_modulus_ = num_bits;
  key_valid_ = true;
  key_type_ = new string("ecc-256");
  key_name_ = new string(name);
  key_usage_ = new string(usage);
  key_owner_ = new string(owner);
  not_before_ = new TimePoint();
  not_after_ = new TimePoint();
  not_before_->TimePointNow();
  not_after_->TimePointLaterBySeconds(*not_before_, secondstolive);
  if (num_bits != 256) {
    LOG(ERROR) << "EccKey::MakeECCKey: only 256 bit keys supported\n";
    return false;
  }
  if (c != nullptr) {
    c_.a_ = new BigNum(*c->a_);
    c_.b_ = new BigNum(*c->b_);
    c_.p_ = new BigNum(*c->p_);
  } else {
    LOG(ERROR) << "EccKey::MakeECCKey: no curve\n";
    return false;
  }
  if (g != nullptr) {
    g_.x_ = new BigNum(*g->x_);
    g_.y_ = new BigNum(*g->y_);
    g_.z_ = new BigNum(*g->z_);
  } else {
    LOG(ERROR) << "EccKey::MakeECCKey: no generator\n";
    return false;
  }

  if (base != nullptr) {
    base_.x_ = new BigNum(*base->x_);
    base_.y_ = new BigNum(*base->y_);
    base_.z_ = new BigNum(*base->z_);
  } else {
    base_.x_ = new BigNum(2 * num_bits / NBITSINUINT64);
    base_.y_ = new BigNum(2 * num_bits / NBITSINUINT64);
    base_.z_ = new BigNum(2 * num_bits / NBITSINUINT64);
  }
  if (order != nullptr) {
    order_of_g_ = new BigNum(*order);
  }
  if (secret != nullptr) {
    a_ = new BigNum(*secret);
  }
  if (base == nullptr && secret != nullptr) {
    EccMult(c_, g_, *secret, base_);
  }
  return true;
}

bool EccKey::GenerateEccKey(string& curve_name, const char* name, const char* usage,
                    const char* owner, double seconds_to_live) {
  BigNum secret(8);

  if (!InitEccCurves()) {
    printf("InitEccCurves failed\n");
    return false;
  }
  secret.ZeroNum();
  if (curve_name == "P-256") {
    // Check
    if (!GetCryptoRand(192, (byte*)secret.value_)) {
      printf("Cant GetCryptoRand\n");
      return false;
    }
    secret.Normalize();
    return MakeEccKey(name, usage, owner, 256, seconds_to_live, &P256_Key.c_,
                    &P256_Key.g_, nullptr, P256_Key.order_of_g_, &secret);
  } else {
    printf("Unknown curve name\n");
    return false;
  }
}

bool CurvePoint::SerializePointToMessage(crypto_point_message& msg) {
  // TODO: z shoud be 1
  msg.set_valid(1);
  if (x_ != nullptr) {
    string* s = ByteToBase64RightToLeft(x_->size_ * sizeof(uint64_t),
                                        (byte*)x_->value_);
    msg.set_x(s->c_str());
    delete s;
  }
  if (y_ != nullptr) {
    string* s = ByteToBase64RightToLeft(y_->size_ * sizeof(uint64_t),
                                        (byte*)y_->value_);
    msg.set_y(s->c_str());
    delete s;
  }
  return true;
}

bool CurvePoint::DeserializePointFromMessage(crypto_point_message& msg) {
  int k;
  int len, bignum_size;

  if (msg.has_x()) {
    len = strlen(msg.x().c_str());
    bignum_size =
        ((len + sizeof(uint64_t) - 1) / sizeof(uint64_t)) * sizeof(uint64_t);
    if (x_ == nullptr) {
      x_ = new BigNum(bignum_size);
    }
    k = Base64ToByteRightToLeft((char*)(msg.x().c_str()),
                                bignum_size * sizeof(uint64_t),
                                (byte*)x_->value_);
    if (k < 0) {
      LOG(ERROR) << "EccCurve::DeserializePointFromMessage: cant encode\n";
    }
    x_->Normalize();
  }
  if (msg.has_y()) {
    len = strlen(msg.y().c_str());
    bignum_size =
        ((len + sizeof(uint64_t) - 1) / sizeof(uint64_t)) * sizeof(uint64_t);
    if (y_ == nullptr) {
      y_ = new BigNum(bignum_size);
    }
    k = Base64ToByteRightToLeft((char*)(msg.y().c_str()),
                                bignum_size * sizeof(uint64_t),
                                (byte*)y_->value_);
    if (k < 0) {
      LOG(ERROR) << "EccCurve::DeserializePointFromMessage: cant encode\n";
    }
    y_->Normalize();
  }
  z_ = new BigNum(1, 1ULL);
  return true;
}

bool EccCurve::SerializeCurveToMessage(crypto_ecc_curve_message& msg) {
  // TODO: fix
  msg.set_bit_modulus_size(256);
  if (p_ != nullptr) {
    string* s = ByteToBase64RightToLeft(p_->size_ * sizeof(uint64_t),
                                        (byte*)p_->value_);
    msg.set_p(s->c_str());
    delete s;
  }
  if (a_ != nullptr) {
    string* s = ByteToBase64RightToLeft(a_->size_ * sizeof(uint64_t),
                                        (byte*)a_->value_);
    msg.set_a(s->c_str());
    delete s;
  }
  if (b_ != nullptr) {
    string* s = ByteToBase64RightToLeft(b_->size_ * sizeof(uint64_t),
                                        (byte*)b_->value_);
    msg.set_b(s->c_str());
    delete s;
  }
  return true;
}

bool EccCurve::DeserializeCurveFromMessage(crypto_ecc_curve_message& msg) {
  int k;
  int len, bignum_size;

  if (msg.has_p()) {
    len = strlen(msg.p().c_str());
    bignum_size =
        ((len + sizeof(uint64_t) - 1) / sizeof(uint64_t)) * sizeof(uint64_t);
    if (p_ == nullptr) {
      p_ = new BigNum(bignum_size);
    }
    k = Base64ToByteRightToLeft((char*)(msg.p().c_str()),
                                bignum_size * sizeof(uint64_t),
                                (byte*)p_->value_);
    if (k < 0) {
      LOG(ERROR) << "EccCurve::DeserializeCurveFromMessage: cant encode\n";
    }
    p_->Normalize();
  }
  if (msg.has_a()) {
    len = strlen(msg.a().c_str());
    bignum_size =
        ((len + sizeof(uint64_t) - 1) / sizeof(uint64_t)) * sizeof(uint64_t);
    if (a_ == nullptr) {
      a_ = new BigNum(bignum_size);
    }
    k = Base64ToByteRightToLeft((char*)(msg.a().c_str()),
                                bignum_size * sizeof(uint64_t),
                                (byte*)a_->value_);
    if (k < 0) {
      LOG(ERROR) << "EccCurve::DeserializeCurveFromMessage: cant encode\n";
    }
    a_->Normalize();
  }
  if (msg.has_b()) {
    len = strlen(msg.b().c_str());
    bignum_size =
        ((len + sizeof(uint64_t) - 1) / sizeof(uint64_t)) * sizeof(uint64_t);
    if (b_ == nullptr) {
      b_ = new BigNum(bignum_size);
    }
    k = Base64ToByteRightToLeft((char*)(msg.b().c_str()),
                                bignum_size * sizeof(uint64_t),
                                (byte*)b_->value_);
    if (k < 0) {
      LOG(ERROR) << "EccCurve::DeserializeCurveFromMessage: cant encode\n";
    }
    b_->Normalize();
  }
  return true;
}

bool EccKey::SerializeKeyToMessage(crypto_ecc_key_message& msg) {
  msg.set_key_type("ecc-256");

  if (a_ != nullptr) {
    string* s = ByteToBase64RightToLeft(a_->size_ * sizeof(uint64_t),
                                        (byte*)a_->value_);
    msg.set_private_nonce(s->c_str());
    delete s;
  }
  if (order_of_g_ != nullptr) {
    string* s = ByteToBase64RightToLeft(order_of_g_->size_ * sizeof(uint64_t),
                                        (byte*)order_of_g_->value_);
    msg.set_order(s->c_str());
    delete s;
  }
  crypto_point_message* g_msg = msg.mutable_generator();
  crypto_point_message* b_msg = msg.mutable_base_point();
  crypto_ecc_curve_message* c_msg = msg.mutable_curve();
  c_.SerializeCurveToMessage(*c_msg);
  g_.SerializePointToMessage(*g_msg);
  base_.SerializePointToMessage(*b_msg);
  return true;
}

bool EccKey::DeserializeKeyFromMessage(crypto_ecc_key_message& msg) {
  int k;

  bit_size_modulus_ = 256;
  int len, bignum_size;
  if (!msg.has_key_type()) return false;

  if (msg.has_private_nonce()) {
    len = strlen(msg.private_nonce().c_str());
    bignum_size =
        ((len + sizeof(uint64_t) - 1) / sizeof(uint64_t)) * sizeof(uint64_t);
    if (a_ == nullptr) {
      a_ = new BigNum(bignum_size);
    }
    k = Base64ToByteRightToLeft((char*)(msg.private_nonce().c_str()),
                                bignum_size * sizeof(uint64_t),
                                (byte*)a_->value_);
    if (k < 0) {
      LOG(ERROR) << "EccCurve::DeserializeKeyFromMessage: cant encode\n";
      a_->Normalize();
    }
  }
  if (msg.has_order()) {
    len = strlen(msg.order().c_str());
    bignum_size =
        ((len + sizeof(uint64_t) - 1) / sizeof(uint64_t)) * sizeof(uint64_t);
    if (order_of_g_ == nullptr) {
      order_of_g_ = new BigNum(bignum_size);
    }
    k = Base64ToByteRightToLeft((char*)(msg.order().c_str()),
                                bignum_size * sizeof(uint64_t),
                                (byte*)order_of_g_->value_);
    order_of_g_->Normalize();
  }

  if (msg.has_curve()) {
    crypto_ecc_curve_message cm = msg.curve();
    c_.DeserializeCurveFromMessage(cm);
  }
  if (msg.has_generator()) {
    crypto_point_message pm = msg.generator();
    g_.DeserializePointFromMessage(pm);
  }
  if (msg.has_base_point()) {
    crypto_point_message pm = msg.base_point();
    base_.DeserializePointFromMessage(pm);
  }
  return true;
}

void EccKey::PrintKey() {
  printf("modulus size: %d bits\n", bit_size_modulus_);
  c_.PrintCurve();

  if (a_ != nullptr) {
    printf("a: ");
    PrintNumToConsole(*a_, 10ULL);
    printf("\n");
  }
  printf("g: ");
  g_.PrintPoint();
  printf("\n");
  if (order_of_g_ != nullptr) {
    printf("order: ");
    PrintNumToConsole(*order_of_g_, 10ULL);
    printf("\n");
  }
  printf("base: ");
  base_.PrintPoint();
  printf("\n");
}

/*
 Curve P-256:
 p= 2^256 − 2^224 + 2^192 + 2^96 − 1:
 (p)_10 = 1157920892103562487626974469494075735300
          86143415290314195533631308867097853951
 (p)_16= ffffffff 00000001 00000000 00000000 00000000 ffffffff
 ffffffff ffffffff
 a = p^256 − 3:
 (a)_10 = 1157920892103562487626974469494075735300
          86143415290314195533631308867097853948
 (a)_16 = ffffffff 00000001 00000000 00000000 00000000 ffffffff
          ffffffff fffffffc
 (b)_10 = 4105836372515214212932612978004726840911
          4441015993725554835256314039467401291
 (b)_16 = 5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6
          3bce3c3e 27d2604b
 Base point G:
 (xG)_16 = 6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0
          f4a13945 d898c296
 (yG)_16 = 4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece
           cbb64068 37bf51f5
 Order q of the point G (and of the elliptic curve group E):
 (q__16 = ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84
          f3b9cac2 fc632551
*/
bool InitEccCurves() {
  if (P256_key_valid) return true;
  TimePoint* time_now = new TimePoint();
  TimePoint* time_later = new TimePoint();

  if (!time_now->TimePointNow()) {
    printf("TimePointNow failed\n");
    return false;
  }
  time_later->TimePointLaterBySeconds(*time_now, 10.0 * COMMON_YEAR_SECONDS);
  P256_Key.key_valid_ = true;
  P256_Key.key_name_ = new string("P-256");
  P256_Key.key_type_ = new string("ecc-256");
  P256_Key.key_usage_ = new string("all");
  P256_Key.key_owner_ = new string("NIST");
  P256_Key.not_before_ = time_now;
  ;
  P256_Key.not_after_ = time_later;

  P256_Key.bit_size_modulus_ = 256;

  P256_Key.c_.p_ = new BigNum(4);
  P256_Key.c_.p_->value_[3] = 0xffffffff00000001ULL;
  P256_Key.c_.p_->value_[2] = 0ULL;
  P256_Key.c_.p_->value_[1] = 0x00000000ffffffffULL;
  P256_Key.c_.p_->value_[0] = 0xffffffffffffffffULL;
  P256_Key.c_.p_->Normalize();

  P256_Key.c_.a_ = new BigNum(4);
  P256_Key.c_.a_->value_[3] = 0xffffffff00000001ULL;
  P256_Key.c_.a_->value_[2] = 0ULL;
  P256_Key.c_.a_->value_[1] = 0x00000000ffffffffULL;
  P256_Key.c_.a_->value_[0] = 0xfffffffffffffffcULL;
  P256_Key.c_.a_->Normalize();

  P256_Key.c_.b_ = new BigNum(4);
  P256_Key.c_.b_->value_[3] = 0x5ac635d8aa3a93e7ULL;
  P256_Key.c_.b_->value_[2] = 0xb3ebbd55769886bcULL;
  P256_Key.c_.b_->value_[1] = 0x651d06b0cc53b0f6ULL;
  P256_Key.c_.b_->value_[0] = 0x3bce3c3e27d2604bULL;
  P256_Key.c_.b_->Normalize();

  P256_Key.bit_size_modulus_ = 256;
  CurvePoint g;
  P256_Key.order_of_g_ = new BigNum(4);
  P256_Key.order_of_g_->value_[3] = 0xffffffff00000000ULL;
  P256_Key.order_of_g_->value_[2] = 0xffffffffffffffffULL;
  P256_Key.order_of_g_->value_[1] = 0xbce6faada7179e84ULL;
  P256_Key.order_of_g_->value_[0] = 0xf3b9cac2fc632551ULL;
  P256_Key.order_of_g_->Normalize();

  P256_Key.g_.x_ = new BigNum(4);
  P256_Key.g_.x_->value_[3] = 0x6b17d1f2e12c4247ULL;
  P256_Key.g_.x_->value_[2] = 0xf8bce6e563a440f2ULL;
  P256_Key.g_.x_->value_[1] = 0x77037d812deb33a0ULL;
  P256_Key.g_.x_->value_[0] = 0xf4a13945d898c296ULL;
  P256_Key.g_.x_->Normalize();
  P256_Key.g_.y_ = new BigNum(4);
  P256_Key.g_.y_->value_[3] = 0x4fe342e2fe1a7f9bULL;
  P256_Key.g_.y_->value_[2] = 0x8ee7eb4a7c0f9e16ULL;
  P256_Key.g_.y_->value_[1] = 0x2bce33576b315eceULL;
  P256_Key.g_.y_->value_[0] = 0xcbb6406837bf51f5ULL;
  P256_Key.g_.y_->Normalize();
  P256_Key.g_.z_ = new BigNum(1, 1ULL);
  ;
  P256_Key.g_.z_->Normalize();
  P256_key_valid = true;
  P256_Key.base_.x_ = nullptr;
  P256_Key.base_.y_ = nullptr;
  P256_Key.base_.z_ = nullptr;
  return true;
}

//  embed message into point M
//  pick k at random
//  send (kG, kBase+M)
bool EccKey::Encrypt(int size, byte* plain, BigNum& k, CurvePoint& pt1,
                     CurvePoint& pt2) {
  BigNum m(c_.p_->capacity_);
  CurvePoint P(c_.p_->capacity_);
  CurvePoint R(c_.p_->capacity_);

  memcpy((byte*)m.value_, plain, size);
  m.Normalize();
  if (!EccEmbed(c_, m, P, 8, 20)) {
    LOG(ERROR) << "EccEmbed error in EccKey::Encrypt\n";
    return false;
  }
#ifdef FASTECCMULT
  if (!FasterEccMult(c_, g_, k, pt1)) {
    LOG(ERROR) << "EccMult error in EccKey::Encrypt\n";
    return false;
  }
  if (!FasterEccMult(c_, base_, k, R)) {
    LOG(ERROR) << "EccMult error in EccKey::Encrypt\n";
    return false;
  }
#else
  if (!EccMult(c_, g_, k, pt1)) {
    LOG(ERROR) << "EccMult error in EccKey::Encrypt\n";
    return false;
  }
  if (!EccMult(c_, base_, k, R)) {
    LOG(ERROR) << "EccMult error in EccKey::Encrypt\n";
    return false;
  }
#endif
  if (!EccAdd(c_, R, P, pt2)) {
    LOG(ERROR) << "EccAdd error in EccKey::Encrypt\n";
    return false;
  }
  return true;
}

//  M= kBase+M-(secret)kG
//  extract message from M
bool EccKey::Decrypt(CurvePoint& pt1, CurvePoint& pt2, int* size, byte* plain) {
  BigNum m(c_.p_->capacity_);
  CurvePoint P(c_.p_->capacity_);
  CurvePoint R(c_.p_->capacity_);

#ifdef FASTECCMULT
  if (!FasterEccMult(c_, pt1, *a_, R)) {
    LOG(ERROR) << "EccMult error in EccKey::Decrypt\n";
    return false;
  }
#else
  if (!EccMult(c_, pt1, *a_, R)) {
    LOG(ERROR) << "EccMult error in EccKey::Decrypt\n";
    return false;
  }
#endif
  if (!EccSub(c_, pt2, R, P)) {
    LOG(ERROR) << "EccAdd error in EccKey::Decrypt\n";
    return false;
  }
  if (!EccExtract(c_, P, m, 8)) {
    LOG(ERROR) << "EccExtract error in EccKey::Decrypt\n";
    return false;
  }
  m.Normalize();
  int n = (BigHighBit(m) + NBITSINBYTE - 1) / NBITSINBYTE;
  if (*size < n) return false;
  *size = n;
  memcpy(plain, (byte*)m.value_, *size);
  return true;
}
