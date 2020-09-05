//
// Copyright 2014 John Manferdelli, All r_ptights r_pteserved.
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

bool curve_point::copy_from(curve_point& pt) {
  x_->copy_from(*pt.x_);
  y_->copy_from(*pt.y_);
  z_->copy_from(*pt.z_);
  return true;
}

bool curve_point::copy_to(curve_point& pt) {
  x_->copy_to(*pt.x_);
  y_->copy_to(*pt.y_);
  z_->copy_to(*pt.z_);
  return true;
}

curve_point::curve_point(curve_point& pt) {
  x_ = new big_num(pt.x_->capacity_);
  x_->copy_from(*pt.x_);
  y_ = new big_num(pt.y_->capacity_);
  y_->copy_from(*pt.y_);
  z_ = new big_num(pt.z_->capacity_);
  z_->copy_from(*pt.z_);
}

curve_point::curve_point(curve_point& pt, int capacity) {
  x_ = new big_num(capacity);
  x_->copy_from(*pt.x_);
  y_ = new big_num(capacity);
  y_->copy_from(*pt.y_);
  z_ = new big_num(capacity);
  z_->copy_from(*pt.z_);
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
    a_->print();
    printf(" x + ");
    b_->print();
    printf(" (mod ");
    p_->print();
    printf(")\n");
  }
}

// Disc= -(4a^3+27b^2) (mod p)

/*
 *  pick parameter k.
 *  x= m<<shift+j
 *  for the first j: x^3+ax+b (mod p) is has a square root, y
 *  point is (x,y)
 */
bool ecc_embed(ecc_curve& c, big_num& m, curve_point& pt, int shift, int trys) {
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
      if (!big_mod_Squarer_ptoot(t1, *c.p_, *pt.y_)) {
        return false;
      }
      pt.x_->copy_from(m_x);
      pt.z_->zero_num();
      pt.z_->value_[0] = 1ULL;
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

bool ecc_extract(ecc_curve& c, curve_point& pt, big_num& m, int shift) {
  big_num t1(2 * c.p_->capacity_);
  big_num t2(2 * c.p_->capacity_);
  big_num t3(2 * c.p_->capacity_);

  m.zero_num();
  if (!big_mod_mult(*pt.x_, *pt.x_, *c.p_, t1)) {
    return false;
  }
  if (!big_mod_mult(*pt.x_, t1, *c.p_, t2)) {
    return false;
  }
  t1.zero_num();
  if (!big_mod_mult(*pt.x_, *c.a_, *c.p_, t1)) {
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
  if (!big_mod_mult(*pt.y_, *pt.y_, *c.p_, t1)) {
    return false;
  }
  if (big_compare(t1, t2) != 0) {
    return false;
  }
  if (!big_shift(*pt.x_, -shift, m)) {
    return false;
  }
  return true;
}

/*
 *  y^2= x^3+ax+b (mod p)
 *  pt=(x1, y1) and q_pt=(x2, y2).  Want pt+q_pt=r_pt=(x3,y3).
 *  if pt= O, r_pt=q_pt.
 *  if q_pt= O, r_pt=pt.
 *  if x1=x2 and y1=-y2, r_pt= O
 *  if x1=x2 and y1+y2!=0, m= (3a1^2+a)/(y1+y2) otherwise
 *    m= (y2-y1)/(x2-x1)
 *    x3= m^2-x1-x2, y3= m(x1-x3)-y1
 */
bool ecc_add(ecc_curve& c, curve_point& pt, curve_point& q_pt, curve_point& r_pt) {
  pt.normalize(*c.p_);
  q_pt.normalize(*c.p_);

  if (pt.is_zero()) {
    return q_pt.copy_to(r_pt);
  }
  if (q_pt.is_zero()) {
    return pt.copy_to(r_pt);
  }
  big_num m(2 * c.p_->size_);
  big_num t1(2 * c.p_->size_);
  big_num t2(2 * c.p_->size_);
  big_num t3(2 * c.p_->size_);

  r_pt.z_->copy_from(big_one);
  if (big_compare(*pt.x_, *q_pt.x_) != 0) {
    if (!big_mod_sub(*q_pt.x_, *pt.x_, *c.p_, t1)) {
      return false;
    }
    if (!big_mod_sub(*q_pt.y_, *pt.y_, *c.p_, t2)) {
      return false;
    }
    if (!big_mod_Div(t2, t1, *c.p_, m)) {
      return false;
    }
  } else {
    if (!big_mod_add(*pt.y_, *q_pt.y_, *c.p_, t1)) {
      return false;
    }
    if (t1.is_zero()) {
      r_pt.make_zero();
      return true;
    }
    if (!big_mod_mult(*pt.x_, *pt.x_, *c.p_, t3)) {
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
  if (!big_mod_sub(t1, *pt.x_, *c.p_, t2)) {
    return false;
  }
  if (!big_mod_sub(t2, *q_pt.x_, *c.p_, *r_pt.x_)) {
    return false;
  }
  t1.zero_num();
  t2.zero_num();
  t3.zero_num();
  if (!big_mod_sub(*pt.x_, *r_pt.x_, *c.p_, t1)) {
    return false;
  }
  if (!big_mod_mult(m, t1, *c.p_, t2)) {
    return false;
  }
  if (!big_mod_sub(t2, *pt.y_, *c.p_, *r_pt.y_)) {
    return false;
  }
  return true;
}

bool ecc_sub(ecc_curve& c, curve_point& pt, curve_point& q_pt, curve_point& r_pt) {
  if (q_pt.is_zero()) {
    r_pt.copy_from(pt);
    return true;
  }

  curve_point minus_q_pt(q_pt);
  big_num t(2 * c.p_->capacity_);
  if (!big_sub(*c.p_, *q_pt.y_, t)) {
    return false;
  }
  if (!big_mod_normalize(t, *c.p_)) {
    return false;
  }
  minus_q_pt.y_->copy_from(t);
  return ecc_add(c, pt, minus_q_pt, r_pt);
}

bool ecc_double(ecc_curve& c, curve_point& pt, curve_point& r_pt) {
  return ecc_add(c, pt, pt, r_pt);
}

//  For Jacobian projective coordinates, see hyperellitptic.org

//  From Cohen, Miyaka, Ono
//  ptrojective addition
//    y^2z=x^3+axz^2+bz^3
//    pt != +- q_pt
//    u= y2z1-y1z2, v=x2z1-x1z2, A= u^2z1z2-v^3-2v^2x1z2
//    x3= vA, y3= u(v^2x1z2-A)-v^3y1z2, z3= v^3z1z2
//    A=u^2z[1]z[2]-v^3-2v^2x[1]z[2]
//  Doubling
//    r_pt= 2pt
//    x3=2hs, y3= w(4B-h) -8y[1]^2s^2, z3= 8s^3
//    w=az1^2+3x1^2, s=y1z1, B= x1y1s, h= w^2-8B
//

bool projective_to_affine(ecc_curve& c, curve_point& pt) {
  big_num x(1 + 2 * c.p_->size_);
  big_num y(1 + 2 * c.p_->size_);
  big_num zinv(1 + 2 * c.p_->size_);

  if (pt.z_->is_zero()) {
    pt.make_zero();
    return true;
  }
  if (pt.z_->is_one()) return true;
  if (!big_mod_Inv(*pt.z_, *c.p_, zinv)) {
    return false;
  }
  if (!big_mod_mult(*pt.x_, zinv, *c.p_, x)) {
    return false;
  }
  if (!big_mod_mult(*pt.y_, zinv, *c.p_, y)) {
    return false;
  }
  pt.x_->copy_from(x);
  pt.y_->copy_from(y);
  pt.z_->copy_from(big_one);
  return true;
}

bool projective_add(ecc_curve& c, curve_point& pt, curve_point& q_pt, curve_point& r_pt) {
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

  // If pt=O, q_pt
  if (pt.z_->is_zero()) {
    r_pt.copy_from(q_pt);
    return true;
  }
  // If q_pt=O, pt
  if (q_pt.z_->is_zero()) {
    r_pt.copy_from(pt);
    return true;
  }
  if (!big_mod_mult(*pt.x_, *q_pt.z_, *c.p_, a1)) {
    return false;
  }
  if (!big_mod_mult(*pt.y_, *q_pt.z_, *c.p_, a2)) {
    return false;
  }
  if (!big_mod_mult(*q_pt.x_, *pt.z_, *c.p_, b1)) {
    return false;
  }
  if (!big_mod_mult(*q_pt.y_, *pt.z_, *c.p_, b2)) {
    return false;
  }

  // If pt= q_pt, use doubling
  if (big_compare(a1, b1) == 0) {
    if (big_compare(a2, b2) == 0) return projective_double(c, pt, r_pt);
    if (!big_mod_add(a2, b2, *c.p_, t)) {
      return false;
    }
    if (t.is_zero()) {
      r_pt.make_zero();
      return true;
    }
  }

  // u= y2z1-y1z2
  if (!big_mod_mult(*q_pt.y_, *pt.z_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(*pt.y_, *q_pt.z_, *c.p_, w)) {
    return false;
  }
  if (!big_mod_sub(t, w, *c.p_, u)) {
    return false;
  }
  // v=x2z1-x1z2
  if (!big_mod_mult(*q_pt.x_, *pt.z_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(*pt.x_, *q_pt.z_, *c.p_, w)) {
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
  if (!big_mod_mult(u_squared, *pt.z_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, *q_pt.z_, *c.p_, t1)) {
    return false;
  }
  if (!big_mod_mult(v_squared, v, *c.p_, t2)) {
    return false;
  }
  if (!big_mod_mult(v_squared, *pt.x_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, *q_pt.z_, *c.p_, t4)) {
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
  if (!big_mod_mult(v, A, *c.p_, *r_pt.x_)) {
    return false;
  }
  // z3= v^3z1z2
  if (!big_mod_mult(*pt.z_, *q_pt.z_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, t2, *c.p_, *r_pt.z_)) {
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
  if (!big_mod_mult(t2, *pt.y_, *c.p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, *q_pt.z_, *c.p_, t4)) {
    return false;
  }
  if (!big_mod_sub(w, t4, *c.p_, *r_pt.y_)) {
    return false;
  }
  return true;
}

bool projective_double(ecc_curve& c, curve_point& pt, curve_point& r_pt) {
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
  if (!big_mod_mult(*pt.z_, *pt.z_, *c.p_, z1_squared)) {
    return false;
  }
  if (!big_mod_mult(*pt.x_, *pt.x_, *c.p_, x1_squared)) {
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
  if (!big_mod_mult(*pt.y_, *pt.z_, *c.p_, s)) {
    return false;
  }
  // B= x1y1s
  if (!big_mod_mult(*pt.x_, *pt.y_, *c.p_, t1)) {
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
  r_pt.x_->copy_from(t2);

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
  r_pt.z_->copy_from(t2);

  // y3= w(4B-h) -8y1^2s^2
  if (!big_mod_mult(*pt.y_, *pt.y_, *c.p_, y1_squared)) {
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
  if (!big_mod_sub(t1, t3, *c.p_, *r_pt.y_)) {
    return false;
  }
  return true;
}

bool projective_point_mult(ecc_curve& c, big_num& x, curve_point& pt, curve_point& r_pt) {
  if (x.is_zero()) {
    r_pt.make_zero();
    return true;
  }
  if (x.is_one()) {
    return r_pt.copy_from(pt);
  }
  if (pt.z_->is_zero()) {
    r_pt.make_zero();
    return true;
  }

  int k = big_high_bit(x);
  int i;
  curve_point double_point(pt, 1 + 2 * c.p_->capacity_);
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

  accum_point.copy_to(r_pt);
  if (x.is_negative()) {
    r_pt.y_->toggle_sign();
  }
  return true;
}

bool ecc_mult(ecc_curve& c, curve_point& pt, big_num& x, curve_point& r_pt) {
  if (x.is_zero()) {
    r_pt.make_zero();
    return true;
  }
  if (x.is_one()) {
    return r_pt.copy_from(pt);
  }
  int k = big_high_bit(x);
  int i;
  curve_point double_point(pt, 1 + 2 * c.p_->capacity_);
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
  accum_point.copy_to(r_pt);
  if (x.is_negative()) {
    r_pt.y_->toggle_sign();
  }
  return true;
}

bool faster_ecc_mult(ecc_curve& c, curve_point& pt, big_num& x, curve_point& r_pt) {
  if (x.is_zero()) {
    r_pt.make_zero();
    return true;
  }
  if (x.is_one()) {
    return r_pt.copy_from(pt);
  }
  if (!projective_point_mult(c, x, pt, r_pt)) {
    return false;
  }
  if (projective_to_affine(c, r_pt)) {
    return false;
  }
  if (x.is_negative()) {
    r_pt.y_->toggle_sign();
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
  if (curve_name == "pt-256") {
    // Check
    if (!GetCryptor_ptand(192, (byte*)secret.value_)) {
      printf("Cant GetCryptor_ptand\n");
      return false;
    }
    secret.normalize();
    return make_ecc_key(name, usage, owner, seconds_to_live, &pt256_Key.c_,
                    &pt256_Key.g_, nullptr, pt256_Key.order_of_g_, &secret);
  } else if (curve_name == "pt-384") {
    // Check
    if (!GetCryptor_ptand(383, (byte*)secret.value_)) {
      printf("Cant GetCryptor_ptand\n");
      return false;
    }
    secret.normalize();
    return make_ecc_key(name, usage, owner, seconds_to_live, &pt384_Key.c_,
                    &pt384_Key.g_, nullptr, pt384_Key.order_of_g_, &secret);
  } else if (curve_name == "pt-521") {
    // Check
    if (!GetCryptor_ptand(520, (byte*)secret.value_)) {
      printf("Cant GetCryptor_ptand\n");
      return false;
    }
    secret.normalize();
    return make_ecc_key(name, usage, owner, seconds_to_live, &pt521_Key.c_,
                    &pt521_Key.g_, nullptr, pt521_Key.order_of_g_, &secret);
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
    a_->print();
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
  Curve pt-256:
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

  Curve pt-384
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

  Curve pt-521
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

  // pt-256

  if (!pt256_key_valid) {

    pt256_Key.bit_size_modulus_ = 256;
    time_now = new time_point();
    time_later = new time_point();

    if (!time_now->time_pointNow()) {
      printf("time_pointNow failed\n");
      return false;
    }
    time_later->time_pointLaterBySeconds(*time_now, 10.0 * COMMON_YEAr_pt_SECONDS);

    pt256_Key.key_name_ = new string("pt-256");
    pt256_Key.key_type_ = new string("ecc-256");
    pt256_Key.key_usage_ = new string("all");
    pt256_Key.key_owner_ = new string("NIST");
    pt256_Key.not_before_ = time_now;
    pt256_Key.not_after_ = time_later;
  
    pt256_Key.c_.modulus_bit_size_ = 256;
    pt256_Key.c_.p_ = new big_num(4);
    pt256_Key.c_.p_->value_[3] = 0xffffffff00000001ULL;
    pt256_Key.c_.p_->value_[2] = 0ULL;
    pt256_Key.c_.p_->value_[1] = 0x00000000ffffffffULL;
    pt256_Key.c_.p_->value_[0] = 0xffffffffffffffffULL;
    pt256_Key.c_.p_->normalize();

    pt256_Key.c_.a_ = new big_num(4);
    pt256_Key.c_.a_->value_[3] = 0xffffffff00000001ULL;
    pt256_Key.c_.a_->value_[2] = 0ULL;
    pt256_Key.c_.a_->value_[1] = 0x00000000ffffffffULL;
    pt256_Key.c_.a_->value_[0] = 0xfffffffffffffffcULL;
    pt256_Key.c_.a_->normalize();

    pt256_Key.c_.b_ = new big_num(4);
    pt256_Key.c_.b_->value_[3] = 0x5ac635d8aa3a93e7ULL;
    pt256_Key.c_.b_->value_[2] = 0xb3ebbd55769886bcULL;
    pt256_Key.c_.b_->value_[1] = 0x651d06b0cc53b0f6ULL;
    pt256_Key.c_.b_->value_[0] = 0x3bce3c3e27d2604bULL;
    pt256_Key.c_.b_->normalize();

    pt256_Key.bit_size_modulus_ = 256;
    pt256_Key.order_of_g_ = new big_num(4);
    pt256_Key.order_of_g_->value_[3] = 0xffffffff00000000ULL;
    pt256_Key.order_of_g_->value_[2] = 0xffffffffffffffffULL;
    pt256_Key.order_of_g_->value_[1] = 0xbce6faada7179e84ULL;
    pt256_Key.order_of_g_->value_[0] = 0xf3b9cac2fc632551ULL;
    pt256_Key.order_of_g_->normalize();

    pt256_Key.g_.x_ = new big_num(4);
    pt256_Key.g_.x_->value_[3] = 0x6b17d1f2e12c4247ULL;
    pt256_Key.g_.x_->value_[2] = 0xf8bce6e563a440f2ULL;
    pt256_Key.g_.x_->value_[1] = 0x77037d812deb33a0ULL;
    pt256_Key.g_.x_->value_[0] = 0xf4a13945d898c296ULL;
    pt256_Key.g_.x_->normalize();
    pt256_Key.g_.y_ = new big_num(4);
    pt256_Key.g_.y_->value_[3] = 0x4fe342e2fe1a7f9bULL;
    pt256_Key.g_.y_->value_[2] = 0x8ee7eb4a7c0f9e16ULL;
    pt256_Key.g_.y_->value_[1] = 0x2bce33576b315eceULL;
    pt256_Key.g_.y_->value_[0] = 0xcbb6406837bf51f5ULL;
    pt256_Key.g_.y_->normalize();
    pt256_Key.g_.z_ = new big_num(1, 1ULL);

    pt256_Key.g_.z_->normalize();
    pt256_key_valid = true;
    pt256_Key.base_.x_ = nullptr;
    pt256_Key.base_.y_ = nullptr;
    pt256_Key.base_.z_ = nullptr;
    pt256_Key.key_valid_ = true;
  }

  // pt-384
  if (!pt384_key_valid) {

    pt384_Key.c_.modulus_bit_size_ = 384;
    time_now = new time_point();
    time_later = new time_point();

    if (!time_now->time_pointNow()) {
      printf("time_pointNow failed\n");
      return false;
    }
    time_later->time_pointLaterBySeconds(*time_now, 10.0 * COMMON_YEAr_pt_SECONDS);

    pt384_Key.key_name_ = new string("pt-384");
    pt384_Key.key_type_ = new string("ecc-384");
    pt384_Key.key_usage_ = new string("all");
    pt384_Key.key_owner_ = new string("NIST");
    pt384_Key.not_before_ = time_now;
    pt384_Key.not_after_ = time_later;

    // p = 2^384 – 2^128 – 2^96 + 2^32 –1
    pt384_Key.c_.p_ = new big_num(6);
    pt384_Key.c_.p_->value_[5] = 0xffffffffffffffffULL;
    pt384_Key.c_.p_->value_[4] = 0xffffffffffffffffULL;
    pt384_Key.c_.p_->value_[3] = 0xffffffffffffffffULL;
    pt384_Key.c_.p_->value_[2] = 0xfffffffffffffffeULL;
    pt384_Key.c_.p_->value_[1] = 0xffffffff00000000ULL;
    pt384_Key.c_.p_->value_[0] = 0x00000000ffffffffULL;
    pt384_Key.c_.p_->normalize();

    pt384_Key.c_.a_ = new big_num(6);
    pt384_Key.c_.a_->value_[5] = 0x79d1e655f868f02fULL;
    pt384_Key.c_.a_->value_[4] = 0xff48dcdee14151ddULL;
    pt384_Key.c_.a_->value_[3] = 0xb80643c1406d0ca1ULL;
    pt384_Key.c_.a_->value_[2] = 0x0dfe6fc52009540aULL;
    pt384_Key.c_.a_->value_[1] = 0x495e8042ea5f744fULL;
    pt384_Key.c_.a_->value_[0] = 0x6e184667cc722483ULL;
    pt384_Key.c_.a_->normalize();

    pt384_Key.c_.b_ = new big_num(6);
    pt384_Key.c_.b_->value_[5] = 0xb3312fa7e23ee7e4ULL;
    pt384_Key.c_.b_->value_[4] = 0x988e056be3f82d19ULL;
    pt384_Key.c_.b_->value_[3] = 0x181d9c6efe814112ULL;
    pt384_Key.c_.b_->value_[2] = 0x0314088f5013875aULL;
    pt384_Key.c_.b_->value_[1] = 0xc656398d8a2ed19dULL;
    pt384_Key.c_.b_->value_[0] = 0x2a85c8edd3ec2aefULL;
    pt384_Key.c_.b_->normalize();

    pt384_Key.bit_size_modulus_ = 384;
    pt384_Key.order_of_g_ = new big_num(6);
    pt384_Key.order_of_g_->value_[5] = 0xffffffffffffffffULL;
    pt384_Key.order_of_g_->value_[4] = 0xffffffffffffffffULL;
    pt384_Key.order_of_g_->value_[3] = 0xffffffffffffffffULL;
    pt384_Key.order_of_g_->value_[2] = 0xc7634d81f4372ddfULL;
    pt384_Key.order_of_g_->value_[1] = 0x581a0db248b0a77aULL;
    pt384_Key.order_of_g_->value_[0] = 0xecec196accc52973ULL;
    pt384_Key.order_of_g_->normalize();

    pt384_Key.g_.x_ = new big_num(6);
    pt384_Key.g_.x_->value_[5] = 0xaa87ca22be8b0537ULL;
    pt384_Key.g_.x_->value_[4] = 0x8eb1c71ef320ad74ULL;
    pt384_Key.g_.x_->value_[3] = 0x6e1d3b628ba79b98ULL;
    pt384_Key.g_.x_->value_[2] = 0x59f741e082542a38ULL;
    pt384_Key.g_.x_->value_[1] = 0x5502f25dbf55296cULL;
    pt384_Key.g_.x_->value_[0] = 0x3a545e3872760ab7ULL;
    pt384_Key.g_.x_->normalize();
    pt384_Key.g_.y_ = new big_num(6);
    pt384_Key.g_.y_->value_[5] = 0x3617de4a96262c6fULL;
    pt384_Key.g_.y_->value_[4] = 0x5d9e98bf9292dc29ULL;
    pt384_Key.g_.y_->value_[3] = 0xf8f41dbd289a147cULL;
    pt384_Key.g_.y_->value_[2] = 0xe9da3113b5f0b8c0ULL;
    pt384_Key.g_.y_->value_[1] = 0x0a60b1ce1d7e819dULL;
    pt384_Key.g_.y_->value_[0] = 0x7a431d7c90ea0e5fULL;
    pt384_Key.g_.y_->normalize();
    pt384_Key.g_.z_ = new big_num(1, 1ULL);

    pt384_Key.g_.z_->normalize();
    pt384_Key.base_.x_ = nullptr;
    pt384_Key.base_.y_ = nullptr;
    pt384_Key.base_.z_ = nullptr;
    pt384_key_valid = true;
    pt384_Key.key_valid_ = true;
  }

  // pt-521
  if (!pt521_key_valid) {

    pt521_Key.c_.modulus_bit_size_ = 521;
    time_now = new time_point();
    time_later = new time_point();

    if (!time_now->time_pointNow()) {
      printf("time_pointNow failed\n");
      return false;
    }
    time_later->time_pointLaterBySeconds(*time_now, 10.0 * COMMON_YEAr_pt_SECONDS);

    pt521_Key.key_name_ = new string("pt-521");
    pt521_Key.key_type_ = new string("ecc-521");
    pt521_Key.key_usage_ = new string("all");
    pt521_Key.key_owner_ = new string("NIST");
    pt521_Key.not_before_ = time_now;
    pt521_Key.not_after_ = time_later;

    pt521_Key.c_.p_ = new big_num(9);
    pt521_Key.c_.p_->value_[8] = 0x1ffULL;
    pt521_Key.c_.p_->value_[7] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[6] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[5] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[4] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[3] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[2] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[1] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->value_[0] = 0xffffffffffffffffULL;
    pt521_Key.c_.p_->normalize();

    pt521_Key.c_.a_ = new big_num(9);
    pt521_Key.c_.a_->value_[8] = 0x0b4ULL;
    pt521_Key.c_.a_->value_[7] = 0x8bfa5f420a349495ULL;
    pt521_Key.c_.a_->value_[6] = 0x39d2bdfc264eeeebULL;
    pt521_Key.c_.a_->value_[5] = 0x077688e44fbf0ad8ULL;
    pt521_Key.c_.a_->value_[4] = 0xf6d0edb37bd6b533ULL;
    pt521_Key.c_.a_->value_[3] = 0x281000518e19f1b9ULL;
    pt521_Key.c_.a_->value_[2] = 0xffbe0fe9ed8a3c22ULL;
    pt521_Key.c_.a_->value_[1] = 0x00b8f875e523868cULL;
    pt521_Key.c_.a_->value_[0] = 0x70c1e5bf55bad637ULL;
    pt521_Key.c_.a_->normalize();

    pt521_Key.c_.b_ = new big_num(9);
    pt521_Key.c_.b_->value_[8] = 0x051ULL;
    pt521_Key.c_.b_->value_[7] = 0x953eb9618e1c9a1fULL;
    pt521_Key.c_.b_->value_[6] = 0x929a21a0b68540eeULL;
    pt521_Key.c_.b_->value_[5] = 0xa2da725b99b315f3ULL;
    pt521_Key.c_.b_->value_[4] = 0xb8b489918ef109e1ULL;
    pt521_Key.c_.b_->value_[3] = 0x56193951ec7e937bULL;
    pt521_Key.c_.b_->value_[2] = 0x1652c0bd3bb1bf07ULL;
    pt521_Key.c_.b_->value_[1] = 0x3573df883d2c34f1ULL;
    pt521_Key.c_.b_->value_[0] = 0xef451fd46b503f00ULL;
    pt521_Key.c_.b_->normalize();

    pt521_Key.bit_size_modulus_ = 521;
    pt521_Key.order_of_g_ = new big_num(9);
    pt521_Key.order_of_g_->value_[8] = 0x01ffULL;
    pt521_Key.order_of_g_->value_[7] = 0xffffffffffffffffULL;
    pt521_Key.order_of_g_->value_[6] = 0xffffffffffffffffULL;
    pt521_Key.order_of_g_->value_[5] = 0xffffffffffffffffULL;
    pt521_Key.order_of_g_->value_[4] = 0xfffffffffffffffaULL;
    pt521_Key.order_of_g_->value_[3] = 0x51868783bf2f966bULL;
    pt521_Key.order_of_g_->value_[2] = 0x7fcc0148f709a5d0ULL;
    pt521_Key.order_of_g_->value_[1] = 0x3bb5c9b8899c47aeULL;
    pt521_Key.order_of_g_->value_[0] = 0xbb6fb71e91386409ULL;
    pt521_Key.order_of_g_->normalize();

    pt521_Key.g_.x_ = new big_num(9);
    pt521_Key.g_.x_->value_[8] = 0xc6ULL;
    pt521_Key.g_.x_->value_[7] = 0x858e06b70404e9cdULL;
    pt521_Key.g_.x_->value_[6] = 0x9e3ecb662395b442ULL;
    pt521_Key.g_.x_->value_[5] = 0x9c648139053fb521ULL;
    pt521_Key.g_.x_->value_[4] = 0xf828af606b4d3dbaULL;
    pt521_Key.g_.x_->value_[3] = 0xa14b5e77efe75928ULL;
    pt521_Key.g_.x_->value_[2] = 0xfe1dc127a2ffa8deULL;
    pt521_Key.g_.x_->value_[1] = 0x3348b3c1856a429bULL;
    pt521_Key.g_.x_->value_[0] = 0xf97e7e31c2e5bd66ULL;
    pt521_Key.g_.x_->normalize();
    pt521_Key.g_.y_ = new big_num(9);
 
    pt521_Key.g_.y_->value_[8] = 0x118ULL;
    pt521_Key.g_.y_->value_[7] = 0x39296a789a3bc004ULL;
    pt521_Key.g_.y_->value_[6] = 0x5c8a5fb42c7d1bd9ULL;
    pt521_Key.g_.y_->value_[5] = 0x98f54449579b4468ULL;
    pt521_Key.g_.y_->value_[4] = 0x17afbd17273e662cULL;
    pt521_Key.g_.y_->value_[3] = 0x97ee72995ef42640ULL;
    pt521_Key.g_.y_->value_[2] = 0xc550b9013fad0761ULL;
    pt521_Key.g_.y_->value_[1] = 0x353c7086a272c240ULL;
    pt521_Key.g_.y_->value_[0] = 0x88be94769fd16650ULL;
    pt521_Key.g_.y_->normalize();
    pt521_Key.g_.z_ = new big_num(1, 1ULL);

    pt521_Key.g_.z_->normalize();
    pt521_Key.base_.x_ = nullptr;
    pt521_Key.base_.y_ = nullptr;
    pt521_Key.base_.z_ = nullptr;
    pt521_key_valid = true;
    pt521_Key.key_valid_ = true;
  }

  return true;
}

//  embed message into point M
//  pick k at random
//  send (kG, kBase+M)
bool ecc::encrypt(int size, byte* plain, big_num& k, curve_point& pt1,
                     curve_point& pt2) {
  big_num m(c_.p_->capacity_);
  curve_point pt(c_.p_->capacity_);
  curve_point r_pt(c_.p_->capacity_);

  memcpy((byte*)m.value_, plain, size);
  m.normalize();
  if (!ecc_embed(c_, m, pt, 8, 20)) {
    return false;
  }
#ifdef FASTECCMULT
  if (!faster_ecc_mult(c_, g_, k, pt1)) {
    return false;
  }
  if (!faster_ecc_mult(c_, base_, k, r_pt)) {
    return false;
  }
#else
  if (!ecc_mult(c_, g_, k, pt1)) {
    return false;
  }
  if (!ecc_mult(c_, base_, k, r_pt)) {
    return false;
  }
#endif
  if (!ecc_add(c_, r_pt, pt, pt2)) {
    return false;
  }
  return true;
}

//  M= kBase+M-(secret)kG
//  extract message from M
bool ecc::decrypt(curve_point& pt1, curve_point& pt2, int* size, byte* plain) {
  big_num m(c_.p_->capacity_);
  curve_point pt(c_.p_->capacity_);
  curve_point r_pt(c_.p_->capacity_);

#ifdef FASTECCMULT
  if (!faster_ecc_mult(c_, pt1, *a_, r_pt)) {
    return false;
  }
#else
  if (!ecc_mult(c_, pt1, *a_, r_pt)) {
    return false;
  }
#endif
  if (!ecc_sub(c_, pt2, r_pt, pt)) {
    return false;
  }
  if (!ecc_extract(c_, pt, m, 8)) {
    return false;
  }
  m.normalize();
  int n = (big_high_bit(m) + NBITSINBYTE - 1) / NBITSINBYTE;
  if (*size < n) return false;
  *size = n;
  memcpy(plain, (byte*)m.value_, *size);
  return true;
}
