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
// File: ecc.cc

#include "crypto_support.h"
#include "big_num.h"
#include "big_num_functions.h"
#include "ecc.h"

#define FASTECCMULT

//  ECC Curve Data
ecc p256_key;
bool p256_key_valid = false;
ecc p384_key;
bool p384_key_valid = false;
ecc p521_key;
bool p521_key_valid = false;


curve_point::curve_point() {
  x_ = nullptr;
  y_ = nullptr;
  z_ = nullptr;
}

curve_point::curve_point(int size) {
  x_ = new big_num(size);
  y_ = new big_num(size);
  z_ = new big_num(size);
  z_->value_[0] = 1ULL;
  z_->normalize();
}

curve_point::curve_point(big_num& x, big_num& y) {
  x_ = new big_num(x.capacity_);
  x_->copy_from(x);
  y_ = new big_num(y.capacity_);
  y_->copy_from(y);
  z_ = new big_num(x.capacity_);
  z_->value_[0] = 1ULL;
  z_->normalize();
}

curve_point::~curve_point() {
  clear();
  if (x_ != nullptr) {
    x_->zero_num();
    delete x_;
    x_ = nullptr;
  }
  if (y_ != nullptr) {
    y_->zero_num();
    delete y_;
    y_ = nullptr;
  }
  if (z_ != nullptr) {
    z_->zero_num();
    delete z_;
    z_ = nullptr;
  }
}

bool curve_point::is_zero() {
  return x_->is_zero() && z_->is_zero() && y_->is_one();
}

void curve_point::make_zero() {
  x_->zero_num();
  y_->copy_from(big_one);
  z_->zero_num();
}

bool curve_point::copy_from(curve_point& P) {
  x_->copy_from(*P.x_);
  y_->copy_from(*P.y_);
  z_->copy_from(*P.z_);
  return true;
}

bool curve_point::copy_to(curve_point& P) {
  x_->copy_to(*P.x_);
  y_->copy_to(*P.y_);
  z_->copy_to(*P.z_);
  return true;
}

curve_point::curve_point(curve_point& P) {
  x_ = new big_num(P.x_->capacity_);
  x_->copy_from(*P.x_);
  y_ = new big_num(P.y_->capacity_);
  y_->copy_from(*P.y_);
  z_ = new big_num(P.z_->capacity_);
  z_->copy_from(*P.z_);
}

curve_point::curve_point(curve_point& P, int capacity) {
  x_ = new big_num(capacity);
  x_->copy_from(*P.x_);
  y_ = new big_num(capacity);
  y_->copy_from(*P.y_);
  z_ = new big_num(capacity);
  z_->copy_from(*P.z_);
}

void curve_point::clear() {
  if (x_ != nullptr) x_->zero_num();
  if (y_ != nullptr) y_->zero_num();
  if (x_ != nullptr) z_->zero_num();
}

bool curve_point::normalize(big_num& p) {
  // TODO
  if (z_->is_zero() || z_->is_one()) return true;
  return false;
}

void curve_point::print() {
  if (x_ != nullptr) {
    printf("[");
    x_->print();
    printf(", ");
    y_->print();
    printf(", ");
    z_->print();
    printf("]");
  }
}

ecc_curve::ecc_curve() {
  a_ = nullptr;
  b_ = nullptr;
  p_ = nullptr;
}

ecc_curve::ecc_curve(int size) {
  a_ = new big_num(size);
  b_ = new big_num(size);
  p_ = new big_num(size);
}

ecc_curve::ecc_curve(big_num& a, big_num& b, big_num& p) {
  a_ = new big_num(a.capacity_);
  a_->copy_from(a);
  b_ = new big_num(b.capacity_);
  b_->copy_from(b);
  p_ = new big_num(p.capacity_);
  p_->copy_from(p);
}

ecc_curve::~ecc_curve() {
  clear();
  if (a_ != nullptr) {
    a_->zero_num();
    delete a_;
    a_ = nullptr;
  }
  if (b_ != nullptr) {
    b_->zero_num();
    delete b_;
    b_ = nullptr;
  }
  if (p_ != nullptr) {
    p_->zero_num();
    delete p_;
    p_ = nullptr;
  }
}

void ecc_curve::clear() {
  if (a_ != nullptr) a_->zero_num();
  if (b_ != nullptr) b_->zero_num();
  if (p_ != nullptr) p_->zero_num();
}

void ecc_curve::print_curve() {
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
bool ecc_embed(ecc_curve& c, big_num& m, curve_point& P, int shift, int trys) {
  big_num m_x(2 * c.p_->capacity_);
  big_num t1(2 * c.p_->capacity_);
  big_num t2(2 * c.p_->capacity_);
  big_num t3(2 * c.p_->capacity_);
  int i;

  if (!big_shift(m, shift, m_x)) {
    return false;
  }
  if (big_compare(*c.p_, m_x) <= 0) {
    return false;
  }
  for (i = 0; i < trys; i++) {
    if (!big_mod_mult(m_x, m_x, *c.p_, t1)) {
      return false;
    }
    if (!big_mod_mult(m_x, t1, *c.p_, t2)) {
      return false;
    }
    t1.zero_num();
    if (!big_mod_mult(m_x, *c.a_, *c.p_, t1)) {
      return false;
    }
    if (!big_mod_add(t1, t2, *c.p_, t3)) {
      return false;
    }
    t1.zero_num();
    t2.zero_num();
    if (!big_mod_add(t3, *c.b_, *c.p_, t1)) {
      return false;
    }
    if (big_mod_IsSquare(t1, *c.p_)) {
      if (!big_mod_SquareRoot(t1, *c.p_, *P.y_)) {
        return false;
      }
      P.x_->copy_from(m_x);
      P.z_->zero_num();
      P.z_->value_[0] = 1ULL;
      break;
    }
    if (!BigUnsignedaddTo(m_x, big_one)) {
      return false;
    }
  }
  if (i >= trys) {
    return false;
  }
  return true;
}

bool ecc_extract(ecc_curve& c, curve_point& P, big_num& m, int shift) {
  big_num t1(2 * c.p_->capacity_);
  big_num t2(2 * c.p_->capacity_);
  big_num t3(2 * c.p_->capacity_);

  m.zero_num();
  if (!big_mod_mult(*P.x_, *P.x_, *c.p_, t1)) {
    return false;
  }
  if (!big_mod_mult(*P.x_, t1, *c.p_, t2)) {
    return false;
  }
  t1.zero_num();
  if (!big_mod_mult(*P.x_, *c.a_, *c.p_, t1)) {
    return false;
  }
  if (!big_mod_add(t1, t2, *c.p_, t3)) {
    return false;
  }
  t2.zero_num();
  if (!big_mod_add(t3, *c.b_, *c.p_, t2)) {
    return false;
  }
  t1.zero_num();
  if (!big_mod_mult(*P.y_, *P.y_, *c.p_, t1)) {
    return false;
  }
  if (big_compare(t1, t2) != 0) {
    return false;
  }
  if (!big_shift(*P.x_, -shift, m)) {
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
bool ecc_add(ecc_curve& c, curve_point& P, curve_point& Q, curve_point& R) {
  P.normalize(*c.p_);
  Q.normalize(*c.p_);

  if (P.is_zero()) {
    return Q.copy_to(R);
  }
  if (Q.is_zero()) {
    return P.copy_to(R);
  }
  big_num m(2 * c.p_->size_);
  big_num t1(2 * c.p_->size_);
  big_num t2(2 * c.p_->size_);
  big_num t3(2 * c.p_->size_);

  R.z_->copy_from(big_one);
  if (big_compare(*P.x_, *Q.x_) != 0) {
    if (!big_mod_sub(*Q.x_, *P.x_, *c.p_, t1)) {
      return false;
    }
    if (!big_mod_sub(*Q.y_, *P.y_, *c.p_, t2)) {
      return false;
    }
    if (!big_mod_Div(t2, t1, *c.p_, m)) {
      return false;
    }
  } else {
    if (!big_mod_add(*P.y_, *Q.y_, *c.p_, t1)) {
      return false;
    }
    if (t1.is_zero()) {
      R.make_zero();
      return true;
    }
    if (!big_mod_mult(*P.x_, *P.x_, *c.p_, t3)) {
      return false;
    }
    if (!big_mod_mult(big_three, t3, *c.p_, t2)) {
      return false;
    }
    t3.zero_num();
    if (!big_mod_add(t2, *c.a_, *c.p_, t3)) {
      return false;
    }
    if (!big_mod_Div(t3, t1, *c.p_, m)) {
      return false;
    }
  }
  t1.zero_num();
  t2.zero_num();
  if (!big_mod_mult(m, m, *c.p_, t1)) {
    return false;
  }
  if (!big_mod_sub(t1, *P.x_, *c.p_, t2)) {
    return false;
  }
  if (!big_mod_sub(t2, *Q.x_, *c.p_, *R.x_)) {
    return false;
  }
  t1.zero_num();
  t2.zero_num();
  t3.zero_num();
  if (!big_mod_sub(*P.x_, *R.x_, *c.p_, t1)) {
    return false;
  }
  if (!big_mod_mult(m, t1, *c.p_, t2)) {
    return false;
  }
  if (!big_mod_sub(t2, *P.y_, *c.p_, *R.y_)) {
    return false;
  }
  return true;
}

bool ecc_sub(ecc_curve& c, curve_point& P, curve_point& Q, curve_point& R) {
  if (Q.is_zero()) {
    R.copy_from(P);
    return true;
  }

  curve_point minus_Q(Q);
  big_num t(2 * c.p_->capacity_);
  if (!big_sub(*c.p_, *Q.y_, t)) {
    return false;
  }
  if (!big_mod_normalize(t, *c.p_)) {
    return false;
  }
  minus_Q.y_->copy_from(t);
  return ecc_add(c, P, minus_Q, R);
}

bool ecc_double(ecc_curve& c, curve_point& P, curve_point& R) {
  return ecc_add(c, P, P, R);
}

//  For Jacobian projective coordinates, see hyperellitptic.org

//  From Cohen, Miyaka, Ono
//  Projective addition
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

bool projective_to_affine(ecc_curve& c, curve_point& P) {
  big_num x(1 + 2 * c.p_->size_);
  big_num y(1 + 2 * c.p_->size_);
  big_num zinv(1 + 2 * c.p_->size_);

  if (P.z_->is_zero()) {
    P.make_zero();
    return true;
  }
  if (P.z_->is_one()) return true;
  if (!big_mod_Inv(*P.z_, *c.p_, zinv)) {
    return false;
  }
  if (!big_mod_mult(*P.x_, zinv, *c.p_, x)) {
    return false;
  }
  if (!big_mod_mult(*P.y_, zinv, *c.p_, y)) {
    return false;
  }
  P.x_->copy_from(x);
  P.y_->copy_from(y);
  P.z_->copy_from(big_one);
  return true;
}

bool projective_add(ecc_curve& c, curve_point& P, curve_point& Q, curve_point& R) {
  big_num u(1 + 2 * c.p_->size_);
  big_num v(1 + 2 * c.p_->size_);
  big_num A(1 + 2 * c.p_->size_);
  big_num u_squared(1 + 2 * c.p_->size_);
  big_num v_squared(1 + 2 * c.p_->size_);
  big_num w(1 + 2 * c.p_->size_);
  big_num t(1 + 2 * c.p_->size_);
  big_num t1(1 + 2 * c.p_->size_);
  big_num t2(1 + 2 * c.p_->size_);
  big_num t3(1 + 2 * c.p_->size_);
  big_num t4(1 + 2 * c.p_->size_);
  big_num a1(1 + 2 * c.p_->size_);
  big_num a2(1 + 2 * c.p_->size_);
  big_num b1(1 + 2 * c.p_->size_);
  big_num b2(1 + 2 * c.p_->size_);

  // If P=O, Q
  if (P.z_->is_zero()) {
    R.copy_from(Q);
    return true;
  }
  // If Q=O, P
  if (Q.z_->is_zero()) {
    R.copy_from(P);
    return true;
  }
  if (!big_mod_mult(*P.x_, *Q.z_, *c.p_, a1)) {
    return false;
  }
  if (!big_mod_mult(*P.y_, *Q.z_, *c.p_, a2)) {
    return false;
  }
  if (!big_mod_mult(*Q.x_, *P.z_, *c.p_, b1)) {
    return false;
  }
  if (!big_mod_mult(*Q.y_, *P.z_, *c.p_, b2)) {
    return false;
  }

  // If P= Q, use doubling
  if (big_compare(a1, b1) == 0) {
    if (big_compare(a2, b2) == 0) return projective_double(c, P, R);
    if (!big_mod_add(a2, b2, *c.p_, t)) {
      return false;
    }
    if (t.is_zero()) {
      R.make_zero();
      return true;
    }
  }

  // u= y2z1-y1z2
  if (!big_mod_mult(*Q.y_, *P.z_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(*P.y_, *Q.z_, *c.p_, w)) {
    return false;
  }
  if (!big_mod_sub(t, w, *c.p_, u)) {
    return false;
  }
  // v=x2z1-x1z2
  if (!big_mod_mult(*Q.x_, *P.z_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(*P.x_, *Q.z_, *c.p_, w)) {
    return false;
  }
  if (!big_mod_sub(t, w, *c.p_, v)) {
    return false;
  }
  // A= u^2z1z2-v^3-2v^2x1z2
  if (!big_mod_mult(u, u, *c.p_, u_squared)) {
    return false;
  }
  if (!big_mod_mult(v, v, *c.p_, v_squared)) {
    return false;
  }
  if (!big_mod_mult(u_squared, *P.z_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, *Q.z_, *c.p_, t1)) {
    return false;
  }
  if (!big_mod_mult(v_squared, v, *c.p_, t2)) {
    return false;
  }
  if (!big_mod_mult(v_squared, *P.x_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, *Q.z_, *c.p_, t4)) {
    return false;
  }
  if (!big_shift(t4, 1, t3)) {
    return false;
  }
  big_mod_normalize(t3, *c.p_);
  t.zero_num();
  if (!big_mod_sub(t1, t2, *c.p_, t)) {
    return false;
  }
  if (!big_mod_sub(t, t3, *c.p_, A)) {
    return false;
  }
  // x3= vA
  if (!big_mod_mult(v, A, *c.p_, *R.x_)) {
    return false;
  }
  // z3= v^3z1z2
  if (!big_mod_mult(*P.z_, *Q.z_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, t2, *c.p_, *R.z_)) {
    return false;
  }
  // y3= u(v^2x1z2-A)-v^3y1z2
  t.zero_num();
  if (!big_mod_sub(t4, A, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, u, *c.p_, w)) {
    return false;
  }
  if (!big_mod_mult(t2, *P.y_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, *Q.z_, *c.p_, t4)) {
    return false;
  }
  if (!big_mod_sub(w, t4, *c.p_, *R.y_)) {
    return false;
  }
  return true;
}

bool projective_double(ecc_curve& c, curve_point& P, curve_point& R) {
  big_num w(1 + 2 * c.p_->size_);
  big_num w_squared(1 + 2 * c.p_->size_);
  big_num s(1 + 2 * c.p_->size_);
  big_num s_squared(1 + 2 * c.p_->size_);
  big_num h(1 + 2 * c.p_->size_);
  big_num B(1 + 2 * c.p_->size_);
  big_num t1(1 + 2 * c.p_->size_);
  big_num t2(1 + 2 * c.p_->size_);
  big_num t3(1 + 2 * c.p_->size_);
  big_num z1_squared(1 + 2 * c.p_->size_);
  big_num x1_squared(1 + 2 * c.p_->size_);
  big_num y1_squared(1 + 2 * c.p_->size_);

  // w=az1^2+3x1^2
  if (!big_mod_mult(*P.z_, *P.z_, *c.p_, z1_squared)) {
    return false;
  }
  if (!big_mod_mult(*P.x_, *P.x_, *c.p_, x1_squared)) {
    return false;
  }
  if (!big_mod_mult(*c.a_, z1_squared, *c.p_, t1)) {
    return false;
  }
  if (!big_mod_mult(big_three, x1_squared, *c.p_, t2)) {
    return false;
  }
  if (!big_mod_add(t1, t2, *c.p_, w)) {
    return false;
  }
  // s=y1z1
  if (!big_mod_mult(*P.y_, *P.z_, *c.p_, s)) {
    return false;
  }
  // B= x1y1s
  if (!big_mod_mult(*P.x_, *P.y_, *c.p_, t1)) {
    return false;
  }
  if (!big_mod_mult(s, t1, *c.p_, B)) {
    return false;
  }
  // h= w^2-8B
  if (!big_mod_mult(w, w, *c.p_, w_squared)) {
    return false;
  }
  t1.zero_num();
  if (!big_shift(B, 3, t1)) {
    return false;
  }
  big_mod_normalize(t1, *c.p_);
  if (!big_mod_sub(w_squared, t1, *c.p_, h)) {
    return false;
  }

  // x3=2hs
  t1.zero_num();
  if (!big_mod_mult(h, s, *c.p_, t1)) {
    return false;
  }
  t2.zero_num();
  if (!big_shift(t1, 1, t2)) {
    return false;
  }
  big_mod_normalize(t2, *c.p_);
  R.x_->copy_from(t2);

  // z3= 8s^3
  if (!big_mod_mult(s, s, *c.p_, s_squared)) {
    return false;
  }
  if (!big_mod_mult(s_squared, s, *c.p_, t1)) {
    return false;
  }
  t2.zero_num();
  if (!big_shift(t1, 3, t2)) {
    return false;
  }
  big_mod_normalize(t2, *c.p_);
  R.z_->copy_from(t2);

  // y3= w(4B-h) -8y1^2s^2
  if (!big_mod_mult(*P.y_, *P.y_, *c.p_, y1_squared)) {
    return false;
  }
  t1.zero_num();
  t2.zero_num();
  if (!big_shift(B, 2, t1)) {
    return false;
  }
  big_mod_normalize(t1, *c.p_);
  if (!big_mod_sub(t1, h, *c.p_, t2)) {
    return false;
  }
  t1.zero_num();
  if (!big_mod_mult(w, t2, *c.p_, t1)) {
    return false;
  }
  if (!big_mod_mult(s_squared, y1_squared, *c.p_, t2)) {
    return false;
  }
  if (!big_shift(t2, 3, t3)) {
    return false;
  }
  big_mod_normalize(t3, *c.p_);
  if (!big_mod_sub(t1, t3, *c.p_, *R.y_)) {
    return false;
  }
  return true;
}

bool projective_point_mult(ecc_curve& c, big_num& x, curve_point& P, curve_point& R) {
  if (x.is_zero()) {
    R.make_zero();
    return true;
  }
  if (x.is_one()) {
    return R.copy_from(P);
  }
  if (P.z_->is_zero()) {
    R.make_zero();
    return true;
  }

  int k = big_high_bit(x);
  int i;
  curve_point double_point(P, 1 + 2 * c.p_->capacity_);
  curve_point accum_point(1 + 2 * c.p_->capacity_);
  curve_point t1(1 + 2 * c.p_->capacity_);

  accum_point.make_zero();
  for (i = 1; i < k; i++) {
    if (big_bit_position_on(x, i)) {
      projective_add(c, accum_point, double_point, t1);
      t1.copy_to(accum_point);
      t1.make_zero();
    }
    if (!projective_double(c, double_point, t1)) {
      return false;
    }
    t1.copy_to(double_point);
    t1.make_zero();
  }
  if (big_bit_position_on(x, i)) {
    projective_add(c, accum_point, double_point, t1);
    t1.copy_to(accum_point);
    t1.make_zero();
  }

  accum_point.copy_to(R);
  if (x.is_negative()) {
    R.y_->toggle_sign();
  }
  return true;
}

bool ecc_mult(ecc_curve& c, curve_point& P, big_num& x, curve_point& R) {
  if (x.is_zero()) {
    R.make_zero();
    return true;
  }
  if (x.is_one()) {
    return R.copy_from(P);
  }
  int k = big_high_bit(x);
  int i;
  curve_point double_point(P, 1 + 2 * c.p_->capacity_);
  curve_point accum_point(1 + 2 * c.p_->capacity_);
  curve_point t1(1 + 2 * c.p_->capacity_);

  accum_point.make_zero();
  for (i = 1; i < k; i++) {
    if (big_bit_position_on(x, i)) {
      ecc_add(c, accum_point, double_point, t1);
      t1.copy_to(accum_point);
      t1.make_zero();
    }
    if (!ecc_double(c, double_point, t1)) {
      return false;
    }
    t1.copy_to(double_point);
    t1.make_zero();
  }
  if (big_bit_position_on(x, i)) {
    ecc_add(c, accum_point, double_point, t1);
    t1.copy_to(accum_point);
    t1.make_zero();
  }
  accum_point.copy_to(R);
  if (x.is_negative()) {
    R.y_->toggle_sign();
  }
  return true;
}

bool faster_ecc_mult(ecc_curve& c, curve_point& P, big_num& x, curve_point& R) {
  if (x.is_zero()) {
    R.make_zero();
    return true;
  }
  if (x.is_one()) {
    return R.copy_from(P);
  }
  if (!projective_point_mult(c, x, P, R)) {
    return false;
  }
  if (projective_to_affine(c, R)) {
    return false;
  }
  if (x.is_negative()) {
    R.y_->toggle_sign();
  }
  return true;
}

ecc::ecc() {
  bit_size_modulus_ = 0;
  a_ = nullptr;
  order_of_g_ = nullptr;
}

ecc::~ecc() {
  if (a_ != nullptr) {
    a_->zero_num();
    delete a_;
  }
  if (order_of_g_ != nullptr) {
    order_of_g_->zero_num();
    delete order_of_g_;
  }
  c_.clear();
  g_.clear();
  base_.clear();
}

bool ecc::make_ecc_key(const char* name, const char* usage, const char* owner,
                        double secondstolive) {

  bit_size_modulus_ = c->modulus_bit_size_;
  key_name_ = new string(name);
  key_usage_ = new string(usage);
  key_owner_ = new string(owner);
  not_before_ = new time_point();
  not_after_ = new time_point();
  not_before_->time_pointNow();
  not_after_->time_pointLaterBySeconds(*not_before_, secondstolive);
  key_valid_ = true;

  if (c->modulus_bit_size_ == 256) {
    key_type_ = new string("ecc-256");
  } else if (c->modulus_bit_size_ == 384) {
    key_type_ = new string("ecc-384");
  } else if (c->modulus_bit_size_ == 521) {
    key_type_ = new string("ecc-521");
  } else {
    return false;
  }
  if (c != nullptr) {
    c_.a_ = new big_num(*c->a_);
    c_.b_ = new big_num(*c->b_);
    c_.p_ = new big_num(*c->p_);
  } else {
    return false;
  }
  if (g != nullptr) {
    g_.x_ = new big_num(*g->x_);
    g_.y_ = new big_num(*g->y_);
    g_.z_ = new big_num(*g->z_);
  } else {
    return false;
  }

  if (base != nullptr) {
    base_.x_ = new big_num(*base->x_);
    base_.y_ = new big_num(*base->y_);
    base_.z_ = new big_num(*base->z_);
  } else {
    base_.x_ = new big_num(2 * (c->modulus_bit_size_+ NBITSINUINT64 - 1) / NBITSINUINT64);
    base_.y_ = new big_num(2 * (c->modulus_bit_size_+ NBITSINUINT64 - 1)/ NBITSINUINT64);
    base_.z_ = new big_num(2 * (c->modulus_bit_size_ + NBITSINUINT64 - 1)/ NBITSINUINT64);
  }
  if (order != nullptr) {
    order_of_g_ = new big_num(*order);
  }
  if (secret != nullptr) {
    a_ = new big_num(*secret);
  }
  if (base == nullptr && secret != nullptr) {
    ecc_mult(c_, g_, *secret, base_);
  }
  return true;
}

bool ecc::generate_ecc(string& curve_name, const char* name, const char* usage,
                    const char* owner, double seconds_to_live) {
  big_num secret(10);

  if (!init_ecc_curves()) {
    printf("init_ecc_curves failed\n");
    return false;
  }
  secret.zero_num();
  if (curve_name == "P-256") {
    // Check
    if (!GetCryptoRand(192, (byte*)secret.value_)) {
      printf("Cant GetCryptoRand\n");
      return false;
    }
    secret.normalize();
    return make_ecc_key(name, usage, owner, seconds_to_live, &P256_Key.c_,
                    &P256_Key.g_, nullptr, P256_Key.order_of_g_, &secret);
  } else if (curve_name == "P-384") {
    // Check
    if (!GetCryptoRand(383, (byte*)secret.value_)) {
      printf("Cant GetCryptoRand\n");
      return false;
    }
    secret.normalize();
    return make_ecc_key(name, usage, owner, seconds_to_live, &P384_Key.c_,
                    &P384_Key.g_, nullptr, P384_Key.order_of_g_, &secret);
  } else if (curve_name == "P-521") {
    // Check
    if (!GetCryptoRand(520, (byte*)secret.value_)) {
      printf("Cant GetCryptoRand\n");
      return false;
    }
    secret.normalize();
    return make_ecc_key(name, usage, owner, seconds_to_live, &P521_Key.c_,
                    &P521_Key.g_, nullptr, P521_Key.order_of_g_, &secret);
  } else {
    printf("Unknown curve name\n");
    return false;
  }
}

void ecc::print() {
  printf("modulus size: %d bits\n", bit_size_modulus_);
  c_.print_curve();

  if (a_ != nullptr) {
    printf("a: ");
    PrintNumToConsole(*a_, 10ULL);
    printf("\n");
  }
  printf("g: ");
  g_.print();
  printf("\n");
  if (order_of_g_ != nullptr) {
    printf("order: ");
    order_of_g_->print();
    printf("\n");
  }
  printf("base: ");
  base_.print();
  printf("\n");
}

/*
  Curve P-256:
    p = 1157920892103562487626974469494075735300861434152903141955
        33631308867097853951
    n = 115792089210356248762697446949407573529996955224135760342
        422259061068512044369
    SEED = c49d3608 86e70493
    c = 7efba166 2985be94 af317768 0104fa0d
    b = 5ac635d8 aa3a93e7 3bce3c3e 27d2604b
    G_x = 6b17d1f2 e12c4247 f4a13945 d898c296
    G_y = 4fe342e2 fe1a7f9b cbb64068 37bf51f5

    p = 2^256 − 2^224 + 2^192 + 2^96 − 1:
    (p)_10 = 1157920892103562487626974469494075735300
            86143415290314195533631308867097853951
    (p)_16= ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff
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

  Curve P-384
    p = 2^384 – 2^128 – 2^96 + 2^32 – 1
    p = 3940200619639447921227904010014361380507973927046544666794
        8293404245721771496870329047266088258938001861606973112319

    n = 3940200619639447921227904010014361380507973927046544666794
        6905279627659399113263569398956308152294913554433653942643
    SEED = a335926a a319a27a 1d00896a 6773a482 7acdac73

    c = 79d1e655 f868f02f ff48dcde e14151dd b80643c1 406d0ca1
        0dfe6fc5 2009540a 495e8042 ea5f744f 6e184667 cc722483
    b = b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112
        0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef
    G x = aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98
          59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7
    G y = 3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c
          e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f 

  Curve P-521
    p = 2^521 – 1
    p = 686479766013060971498190079908139321726943530014330540939
        446345918554318339765605212255964066145455497729631139148
        0858037121987999716643812574028291115057151
    n = 686479766013060971498190079908139321726943530014330540939
        446345918554318339765539424505774633321719753296399637136
        3321113864768612440380340372808892707005449
    SEED = d09e8800 291cb853 96cc6717 393284aa a0da64ba
    c = 0b4 8bfa5f42 0a349495 39d2bdfc 264eeeeb 077688e4
        4fbf0ad8 f6d0edb3 7bd6b533 28100051 8e19f1b9 ffbe0fe9
        ed8a3c22 00b8f875 e523868c 70c1e5bf 55bad637
    b = 051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b
        99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd
        3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00
    G x = c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139
          053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127
          a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66
    G y = 118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449
          579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901
          3fad0761 353c7086 a272c240 88be9476 9fd16650
*/

bool init_ecc_curves() {

  time_point* time_now = nullptr;
  time_point* time_later = nullptr;

  // P-256

  if (!P256_key_valid) {

    P256_Key.bit_size_modulus_ = 256;
    time_now = new time_point();
    time_later = new time_point();

    if (!time_now->time_pointNow()) {
      printf("time_pointNow failed\n");
      return false;
    }
    time_later->time_pointLaterBySeconds(*time_now, 10.0 * COMMON_YEAR_SECONDS);

    P256_Key.key_name_ = new string("P-256");
    P256_Key.key_type_ = new string("ecc-256");
    P256_Key.key_usage_ = new string("all");
    P256_Key.key_owner_ = new string("NIST");
    P256_Key.not_before_ = time_now;
    P256_Key.not_after_ = time_later;
  
    P256_Key.c_.modulus_bit_size_ = 256;
    P256_Key.c_.p_ = new big_num(4);
    P256_Key.c_.p_->value_[3] = 0xffffffff00000001ULL;
    P256_Key.c_.p_->value_[2] = 0ULL;
    P256_Key.c_.p_->value_[1] = 0x00000000ffffffffULL;
    P256_Key.c_.p_->value_[0] = 0xffffffffffffffffULL;
    P256_Key.c_.p_->normalize();

    P256_Key.c_.a_ = new big_num(4);
    P256_Key.c_.a_->value_[3] = 0xffffffff00000001ULL;
    P256_Key.c_.a_->value_[2] = 0ULL;
    P256_Key.c_.a_->value_[1] = 0x00000000ffffffffULL;
    P256_Key.c_.a_->value_[0] = 0xfffffffffffffffcULL;
    P256_Key.c_.a_->normalize();

    P256_Key.c_.b_ = new big_num(4);
    P256_Key.c_.b_->value_[3] = 0x5ac635d8aa3a93e7ULL;
    P256_Key.c_.b_->value_[2] = 0xb3ebbd55769886bcULL;
    P256_Key.c_.b_->value_[1] = 0x651d06b0cc53b0f6ULL;
    P256_Key.c_.b_->value_[0] = 0x3bce3c3e27d2604bULL;
    P256_Key.c_.b_->normalize();

    P256_Key.bit_size_modulus_ = 256;
    P256_Key.order_of_g_ = new big_num(4);
    P256_Key.order_of_g_->value_[3] = 0xffffffff00000000ULL;
    P256_Key.order_of_g_->value_[2] = 0xffffffffffffffffULL;
    P256_Key.order_of_g_->value_[1] = 0xbce6faada7179e84ULL;
    P256_Key.order_of_g_->value_[0] = 0xf3b9cac2fc632551ULL;
    P256_Key.order_of_g_->normalize();

    P256_Key.g_.x_ = new big_num(4);
    P256_Key.g_.x_->value_[3] = 0x6b17d1f2e12c4247ULL;
    P256_Key.g_.x_->value_[2] = 0xf8bce6e563a440f2ULL;
    P256_Key.g_.x_->value_[1] = 0x77037d812deb33a0ULL;
    P256_Key.g_.x_->value_[0] = 0xf4a13945d898c296ULL;
    P256_Key.g_.x_->normalize();
    P256_Key.g_.y_ = new big_num(4);
    P256_Key.g_.y_->value_[3] = 0x4fe342e2fe1a7f9bULL;
    P256_Key.g_.y_->value_[2] = 0x8ee7eb4a7c0f9e16ULL;
    P256_Key.g_.y_->value_[1] = 0x2bce33576b315eceULL;
    P256_Key.g_.y_->value_[0] = 0xcbb6406837bf51f5ULL;
    P256_Key.g_.y_->normalize();
    P256_Key.g_.z_ = new big_num(1, 1ULL);

    P256_Key.g_.z_->normalize();
    P256_key_valid = true;
    P256_Key.base_.x_ = nullptr;
    P256_Key.base_.y_ = nullptr;
    P256_Key.base_.z_ = nullptr;
    P256_Key.key_valid_ = true;
  }

  // P-384
  if (!P384_key_valid) {

    P384_Key.c_.modulus_bit_size_ = 384;
    time_now = new time_point();
    time_later = new time_point();

    if (!time_now->time_pointNow()) {
      printf("time_pointNow failed\n");
      return false;
    }
    time_later->time_pointLaterBySeconds(*time_now, 10.0 * COMMON_YEAR_SECONDS);

    P384_Key.key_name_ = new string("P-384");
    P384_Key.key_type_ = new string("ecc-384");
    P384_Key.key_usage_ = new string("all");
    P384_Key.key_owner_ = new string("NIST");
    P384_Key.not_before_ = time_now;
    P384_Key.not_after_ = time_later;

    // p = 2^384 – 2^128 – 2^96 + 2^32 –1
    P384_Key.c_.p_ = new big_num(6);
    P384_Key.c_.p_->value_[5] = 0xffffffffffffffffULL;
    P384_Key.c_.p_->value_[4] = 0xffffffffffffffffULL;
    P384_Key.c_.p_->value_[3] = 0xffffffffffffffffULL;
    P384_Key.c_.p_->value_[2] = 0xfffffffffffffffeULL;
    P384_Key.c_.p_->value_[1] = 0xffffffff00000000ULL;
    P384_Key.c_.p_->value_[0] = 0x00000000ffffffffULL;
    P384_Key.c_.p_->normalize();

    P384_Key.c_.a_ = new big_num(6);
    P384_Key.c_.a_->value_[5] = 0x79d1e655f868f02fULL;
    P384_Key.c_.a_->value_[4] = 0xff48dcdee14151ddULL;
    P384_Key.c_.a_->value_[3] = 0xb80643c1406d0ca1ULL;
    P384_Key.c_.a_->value_[2] = 0x0dfe6fc52009540aULL;
    P384_Key.c_.a_->value_[1] = 0x495e8042ea5f744fULL;
    P384_Key.c_.a_->value_[0] = 0x6e184667cc722483ULL;
    P384_Key.c_.a_->normalize();

    P384_Key.c_.b_ = new big_num(6);
    P384_Key.c_.b_->value_[5] = 0xb3312fa7e23ee7e4ULL;
    P384_Key.c_.b_->value_[4] = 0x988e056be3f82d19ULL;
    P384_Key.c_.b_->value_[3] = 0x181d9c6efe814112ULL;
    P384_Key.c_.b_->value_[2] = 0x0314088f5013875aULL;
    P384_Key.c_.b_->value_[1] = 0xc656398d8a2ed19dULL;
    P384_Key.c_.b_->value_[0] = 0x2a85c8edd3ec2aefULL;
    P384_Key.c_.b_->normalize();

    P384_Key.bit_size_modulus_ = 384;
    P384_Key.order_of_g_ = new big_num(6);
    P384_Key.order_of_g_->value_[5] = 0xffffffffffffffffULL;
    P384_Key.order_of_g_->value_[4] = 0xffffffffffffffffULL;
    P384_Key.order_of_g_->value_[3] = 0xffffffffffffffffULL;
    P384_Key.order_of_g_->value_[2] = 0xc7634d81f4372ddfULL;
    P384_Key.order_of_g_->value_[1] = 0x581a0db248b0a77aULL;
    P384_Key.order_of_g_->value_[0] = 0xecec196accc52973ULL;
    P384_Key.order_of_g_->normalize();

    P384_Key.g_.x_ = new big_num(6);
    P384_Key.g_.x_->value_[5] = 0xaa87ca22be8b0537ULL;
    P384_Key.g_.x_->value_[4] = 0x8eb1c71ef320ad74ULL;
    P384_Key.g_.x_->value_[3] = 0x6e1d3b628ba79b98ULL;
    P384_Key.g_.x_->value_[2] = 0x59f741e082542a38ULL;
    P384_Key.g_.x_->value_[1] = 0x5502f25dbf55296cULL;
    P384_Key.g_.x_->value_[0] = 0x3a545e3872760ab7ULL;
    P384_Key.g_.x_->normalize();
    P384_Key.g_.y_ = new big_num(6);
    P384_Key.g_.y_->value_[5] = 0x3617de4a96262c6fULL;
    P384_Key.g_.y_->value_[4] = 0x5d9e98bf9292dc29ULL;
    P384_Key.g_.y_->value_[3] = 0xf8f41dbd289a147cULL;
    P384_Key.g_.y_->value_[2] = 0xe9da3113b5f0b8c0ULL;
    P384_Key.g_.y_->value_[1] = 0x0a60b1ce1d7e819dULL;
    P384_Key.g_.y_->value_[0] = 0x7a431d7c90ea0e5fULL;
    P384_Key.g_.y_->normalize();
    P384_Key.g_.z_ = new big_num(1, 1ULL);

    P384_Key.g_.z_->normalize();
    P384_Key.base_.x_ = nullptr;
    P384_Key.base_.y_ = nullptr;
    P384_Key.base_.z_ = nullptr;
    P384_key_valid = true;
    P384_Key.key_valid_ = true;
  }

  // P-521
  if (!P521_key_valid) {

    P521_Key.c_.modulus_bit_size_ = 521;
    time_now = new time_point();
    time_later = new time_point();

    if (!time_now->time_pointNow()) {
      printf("time_pointNow failed\n");
      return false;
    }
    time_later->time_pointLaterBySeconds(*time_now, 10.0 * COMMON_YEAR_SECONDS);

    P521_Key.key_name_ = new string("P-521");
    P521_Key.key_type_ = new string("ecc-521");
    P521_Key.key_usage_ = new string("all");
    P521_Key.key_owner_ = new string("NIST");
    P521_Key.not_before_ = time_now;
    P521_Key.not_after_ = time_later;

    P521_Key.c_.p_ = new big_num(9);
    P521_Key.c_.p_->value_[8] = 0x1ffULL;
    P521_Key.c_.p_->value_[7] = 0xffffffffffffffffULL;
    P521_Key.c_.p_->value_[6] = 0xffffffffffffffffULL;
    P521_Key.c_.p_->value_[5] = 0xffffffffffffffffULL;
    P521_Key.c_.p_->value_[4] = 0xffffffffffffffffULL;
    P521_Key.c_.p_->value_[3] = 0xffffffffffffffffULL;
    P521_Key.c_.p_->value_[2] = 0xffffffffffffffffULL;
    P521_Key.c_.p_->value_[1] = 0xffffffffffffffffULL;
    P521_Key.c_.p_->value_[0] = 0xffffffffffffffffULL;
    P521_Key.c_.p_->normalize();

    P521_Key.c_.a_ = new big_num(9);
    P521_Key.c_.a_->value_[8] = 0x0b4ULL;
    P521_Key.c_.a_->value_[7] = 0x8bfa5f420a349495ULL;
    P521_Key.c_.a_->value_[6] = 0x39d2bdfc264eeeebULL;
    P521_Key.c_.a_->value_[5] = 0x077688e44fbf0ad8ULL;
    P521_Key.c_.a_->value_[4] = 0xf6d0edb37bd6b533ULL;
    P521_Key.c_.a_->value_[3] = 0x281000518e19f1b9ULL;
    P521_Key.c_.a_->value_[2] = 0xffbe0fe9ed8a3c22ULL;
    P521_Key.c_.a_->value_[1] = 0x00b8f875e523868cULL;
    P521_Key.c_.a_->value_[0] = 0x70c1e5bf55bad637ULL;
    P521_Key.c_.a_->normalize();

    P521_Key.c_.b_ = new big_num(9);
    P521_Key.c_.b_->value_[8] = 0x051ULL;
    P521_Key.c_.b_->value_[7] = 0x953eb9618e1c9a1fULL;
    P521_Key.c_.b_->value_[6] = 0x929a21a0b68540eeULL;
    P521_Key.c_.b_->value_[5] = 0xa2da725b99b315f3ULL;
    P521_Key.c_.b_->value_[4] = 0xb8b489918ef109e1ULL;
    P521_Key.c_.b_->value_[3] = 0x56193951ec7e937bULL;
    P521_Key.c_.b_->value_[2] = 0x1652c0bd3bb1bf07ULL;
    P521_Key.c_.b_->value_[1] = 0x3573df883d2c34f1ULL;
    P521_Key.c_.b_->value_[0] = 0xef451fd46b503f00ULL;
    P521_Key.c_.b_->normalize();

    P521_Key.bit_size_modulus_ = 521;
    P521_Key.order_of_g_ = new big_num(9);
    P521_Key.order_of_g_->value_[8] = 0x01ffULL;
    P521_Key.order_of_g_->value_[7] = 0xffffffffffffffffULL;
    P521_Key.order_of_g_->value_[6] = 0xffffffffffffffffULL;
    P521_Key.order_of_g_->value_[5] = 0xffffffffffffffffULL;
    P521_Key.order_of_g_->value_[4] = 0xfffffffffffffffaULL;
    P521_Key.order_of_g_->value_[3] = 0x51868783bf2f966bULL;
    P521_Key.order_of_g_->value_[2] = 0x7fcc0148f709a5d0ULL;
    P521_Key.order_of_g_->value_[1] = 0x3bb5c9b8899c47aeULL;
    P521_Key.order_of_g_->value_[0] = 0xbb6fb71e91386409ULL;
    P521_Key.order_of_g_->normalize();

    P521_Key.g_.x_ = new big_num(9);
    P521_Key.g_.x_->value_[8] = 0xc6ULL;
    P521_Key.g_.x_->value_[7] = 0x858e06b70404e9cdULL;
    P521_Key.g_.x_->value_[6] = 0x9e3ecb662395b442ULL;
    P521_Key.g_.x_->value_[5] = 0x9c648139053fb521ULL;
    P521_Key.g_.x_->value_[4] = 0xf828af606b4d3dbaULL;
    P521_Key.g_.x_->value_[3] = 0xa14b5e77efe75928ULL;
    P521_Key.g_.x_->value_[2] = 0xfe1dc127a2ffa8deULL;
    P521_Key.g_.x_->value_[1] = 0x3348b3c1856a429bULL;
    P521_Key.g_.x_->value_[0] = 0xf97e7e31c2e5bd66ULL;
    P521_Key.g_.x_->normalize();
    P521_Key.g_.y_ = new big_num(9);
 
    P521_Key.g_.y_->value_[8] = 0x118ULL;
    P521_Key.g_.y_->value_[7] = 0x39296a789a3bc004ULL;
    P521_Key.g_.y_->value_[6] = 0x5c8a5fb42c7d1bd9ULL;
    P521_Key.g_.y_->value_[5] = 0x98f54449579b4468ULL;
    P521_Key.g_.y_->value_[4] = 0x17afbd17273e662cULL;
    P521_Key.g_.y_->value_[3] = 0x97ee72995ef42640ULL;
    P521_Key.g_.y_->value_[2] = 0xc550b9013fad0761ULL;
    P521_Key.g_.y_->value_[1] = 0x353c7086a272c240ULL;
    P521_Key.g_.y_->value_[0] = 0x88be94769fd16650ULL;
    P521_Key.g_.y_->normalize();
    P521_Key.g_.z_ = new big_num(1, 1ULL);

    P521_Key.g_.z_->normalize();
    P521_Key.base_.x_ = nullptr;
    P521_Key.base_.y_ = nullptr;
    P521_Key.base_.z_ = nullptr;
    P521_key_valid = true;
    P521_Key.key_valid_ = true;
  }

  return true;
}

//  embed message into point M
//  pick k at random
//  send (kG, kBase+M)
bool ecc::encrypt(int size, byte* plain, big_num& k, curve_point& pt1,
                     curve_point& pt2) {
  big_num m(c_.p_->capacity_);
  curve_point P(c_.p_->capacity_);
  curve_point R(c_.p_->capacity_);

  memcpy((byte*)m.value_, plain, size);
  m.normalize();
  if (!ecc_embed(c_, m, P, 8, 20)) {
    return false;
  }
#ifdef FASTECCMULT
  if (!faster_ecc_mult(c_, g_, k, pt1)) {
    return false;
  }
  if (!faster_ecc_mult(c_, base_, k, R)) {
    return false;
  }
#else
  if (!ecc_mult(c_, g_, k, pt1)) {
    return false;
  }
  if (!ecc_mult(c_, base_, k, R)) {
    return false;
  }
#endif
  if (!ecc_add(c_, R, P, pt2)) {
    return false;
  }
  return true;
}

//  M= kBase+M-(secret)kG
//  extract message from M
bool ecc::decrypt(curve_point& pt1, curve_point& pt2, int* size, byte* plain) {
  big_num m(c_.p_->capacity_);
  curve_point P(c_.p_->capacity_);
  curve_point R(c_.p_->capacity_);

#ifdef FASTECCMULT
  if (!faster_ecc_mult(c_, pt1, *a_, R)) {
    return false;
  }
#else
  if (!ecc_mult(c_, pt1, *a_, R)) {
    return false;
  }
#endif
  if (!ecc_sub(c_, pt2, R, P)) {
    return false;
  }
  if (!ecc_Extract(c_, P, m, 8)) {
    return false;
  }
  m.normalize();
  int n = (big_high_bit(m) + NBITSINBYTE - 1) / NBITSINBYTE;
  if (*size < n) return false;
  *size = n;
  memcpy(plain, (byte*)m.value_, *size);
  return true;
}
