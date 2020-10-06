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
#include "ecc_curve_data.h"

#define FASTECCMULT

curve_point::curve_point() {
  x_ = nullptr;
  y_ = nullptr;
  z_ = nullptr;
}

curve_point::curve_point(int size) {
  x_ = new big_num(size);
  y_ = new big_num(size);
  z_ = new big_num(size, 1ULL);
  z_->normalize();
}

curve_point::~curve_point() {
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

bool curve_point::is_equal(curve_point& p1) {
  if (big_compare(*p1.x_, *x_) != 0)
    return false;
  if (big_compare(*p1.y_, *y_) != 0)
    return false;
  if (big_compare(*p1.z_, *z_) != 0)
    return false;
  return true;
}

bool curve_point::copy_from(curve_point& pt) {
  if (pt.x_ == nullptr || pt.y_ == nullptr || pt.z_ == nullptr)
    return false;
  if (x_ == nullptr || y_ == nullptr || z_ == nullptr)
    return false;
  x_->copy_from(*pt.x_);
  y_->copy_from(*pt.y_);
  z_->copy_from(*pt.z_);
  return true;
}

bool curve_point::copy_to(curve_point& pt) {
  if (pt.x_ == nullptr || pt.y_ == nullptr || pt.z_ == nullptr)
    return false;
  if (x_ == nullptr || y_ == nullptr || z_ == nullptr)
    return false;
  x_->copy_to(*pt.x_);
  y_->copy_to(*pt.y_);
  z_->copy_to(*pt.z_);
  return true;
}

curve_point::curve_point(curve_point& pt) {
  if (pt.x_ == nullptr || pt.y_ == nullptr || pt.z_ == nullptr)
    return;
  int n = pt.x_->capacity_;
  if (pt.y_->capacity_ > n)
    n = pt.y_->capacity_;
  if (pt.z_->capacity_ > n)
    n = pt.z_->capacity_;
  x_ = new big_num(n);
  x_->copy_from(*pt.x_);
  y_ = new big_num(n);
  y_->copy_from(*pt.y_);
  z_ = new big_num(n);
  z_->copy_from(*pt.z_);
}

curve_point::curve_point(curve_point& pt, int capacity) {
  if (pt.x_ == nullptr || pt.y_ == nullptr || pt.z_ == nullptr)
    return;
  if (pt.x_->size() > capacity)
    capacity = pt.x_->size();
  if (pt.y_->size() > capacity)
    capacity = pt.y_->size();
  if (pt.z_->size() > capacity)
    capacity = pt.z_->size();
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
  if (z_ != nullptr) z_->zero_num();
}

bool curve_point::normalize(big_num& p) {
  if (z_->is_zero() || z_->is_one())
    return true;
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
  curve_a_ = nullptr;
  curve_b_ = nullptr;
  curve_p_ = nullptr;
}

ecc_curve::ecc_curve(int size) {
  curve_a_ = new big_num(size);
  curve_b_ = new big_num(size);
  curve_p_ = new big_num(size);
}

ecc_curve::~ecc_curve() {
  clear();
  if (curve_a_ != nullptr) {
    curve_a_->zero_num();
    delete curve_a_;
    curve_a_ = nullptr;
  }
  if (curve_b_ != nullptr) {
    curve_b_->zero_num();
    delete curve_b_;
    curve_b_ = nullptr;
  }
  if (curve_p_ != nullptr) {
    curve_p_->zero_num();
    delete curve_p_;
    curve_p_ = nullptr;
  }
}

void ecc_curve::clear() {
  if (curve_a_ != nullptr) curve_a_->zero_num();
  if (curve_b_ != nullptr) curve_b_->zero_num();
  if (curve_p_ != nullptr) curve_p_->zero_num();
}

void ecc_curve::print_curve() {
  if (curve_a_ != nullptr) {
    printf("Curve: y^2= x^3 + ");
    curve_a_->print();
    printf(" x + ");
    curve_b_->print();
    printf(" (mod ");
    curve_p_->print();
    printf(")\n");
  }
}

bool ecc_curve::copy_from(ecc_curve& c) {
  prime_bit_size_ = c.prime_bit_size_;
  curve_p_->copy_from(*c.curve_p_);
  curve_a_->copy_from(*c.curve_a_);
  curve_b_->copy_from(*c.curve_b_);
  return true;
}

// Disc= -(4a^3+27b^2) (mod p)
bool discriminant(ecc_curve& c, big_num& r) {
  big_num t1(2 * c.curve_p_->capacity_);
  big_num t2(2 * c.curve_p_->capacity_);
  big_num t3(2 * c.curve_p_->capacity_);
  big_num t4(2 * c.curve_p_->capacity_);

  t1.value_[0] = 27;
  t1.normalize();
  if (!big_mod_mult(t1, *c.curve_b_, *c.curve_p_, t2))
    return false;
  if (!big_mod_mult(t2, *c.curve_b_, *c.curve_p_, t4))
    return false;
  t1.zero_num();
  t2.zero_num();
  t3.zero_num();
  if (!big_mod_mult(big_four, *c.curve_a_, *c.curve_p_, t1))
    return false;
  if (!big_mod_mult(t1, *c.curve_a_, *c.curve_p_, t2))
    return false;
  if (!big_mod_mult(t2, *c.curve_a_, *c.curve_p_, t3))
    return false;
  t1.zero_num();
  t2.zero_num();
  if (!big_mod_add(t3, t4, *c.curve_p_, t2))
    return false;
  if (!big_mod_sub(*c.curve_p_, t4, *c.curve_p_, r))
    return false;
  return true;
}

/*
 *  pick parameter k.
 *  x= m<<shift+j
 *  for the first j: x^3+ax+b (mod p) is has a square root, y
 *  point is (x,y)
 */
bool ecc_embed(ecc_curve& c, big_num& m, curve_point& pt, int shift, int trys) {
  big_num m_x(2 * c.curve_p_->capacity_);
  big_num t1(2 * c.curve_p_->capacity_);
  big_num t2(2 * c.curve_p_->capacity_);
  big_num t3(2 * c.curve_p_->capacity_);
  int i;

  if (!big_shift(m, shift, m_x)) {
    return false;
  }
  if (big_compare(*c.curve_p_, m_x) <= 0) {
    return false;
  }
  for (i = 0; i < trys; i++) {
    if (!big_mod_mult(m_x, m_x, *c.curve_p_, t1)) {
      return false;
    }
    if (!big_mod_mult(m_x, t1, *c.curve_p_, t2)) {
      return false;
    }
    t1.zero_num();
    if (!big_mod_mult(m_x, *c.curve_a_, *c.curve_p_, t1)) {
      return false;
    }
    if (!big_mod_add(t1, t2, *c.curve_p_, t3)) {
      return false;
    }
    t1.zero_num();
    t2.zero_num();
    if (!big_mod_add(t3, *c.curve_b_, *c.curve_p_, t1)) {
      return false;
    }
    if (big_mod_is_square(t1, *c.curve_p_)) {
      if (!big_mod_square_root(t1, *c.curve_p_, *pt.y_)) {
        return false;
      }
      pt.x_->copy_from(m_x);
      pt.z_->zero_num();
      pt.z_->value_[0] = 1ULL;
      break;
    }
    if (!big_unsigned_add_to(m_x, big_one)) {
      return false;
    }
  }
  if (i >= trys) {
    return false;
  }
  return true;
}

bool ecc_extract(ecc_curve& c, curve_point& pt, big_num& m, int shift) {
  big_num t1(2 * c.curve_p_->capacity_);
  big_num t2(2 * c.curve_p_->capacity_);
  big_num t3(2 * c.curve_p_->capacity_);

  m.zero_num();
  if (!big_mod_mult(*pt.x_, *pt.x_, *c.curve_p_, t1)) {
    return false;
  }
  if (!big_mod_mult(*pt.x_, t1, *c.curve_p_, t2)) {
    return false;
  }
  t1.zero_num();
  if (!big_mod_mult(*pt.x_, *c.curve_a_, *c.curve_p_, t1)) {
    return false;
  }
  if (!big_mod_add(t1, t2, *c.curve_p_, t3)) {
    return false;
  }
  t2.zero_num();
  if (!big_mod_add(t3, *c.curve_b_, *c.curve_p_, t2)) {
    return false;
  }
  t1.zero_num();
  if (!big_mod_mult(*pt.y_, *pt.y_, *c.curve_p_, t1)) {
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

// see ecc.h for description
bool ecc_add(ecc_curve& c, curve_point& p_pt, curve_point& q_pt, curve_point& r_pt) {
  p_pt.normalize(*c.curve_p_);
  q_pt.normalize(*c.curve_p_);

  if (p_pt.is_zero()) {
    return q_pt.copy_to(r_pt);
  }
  if (q_pt.is_zero()) {
    return p_pt.copy_to(r_pt);
  }
  big_num m(2 * c.curve_p_->size_);
  big_num t1(2 * c.curve_p_->size_);
  big_num t2(2 * c.curve_p_->size_);
  big_num t3(2 * c.curve_p_->size_);

  r_pt.z_->copy_from(big_one);

  if (big_compare(*p_pt.x_, *q_pt.x_) != 0) {
    if (!big_mod_sub(*q_pt.x_, *p_pt.x_, *c.curve_p_, t1)) {
      return false;
    }
    if (!big_mod_sub(*q_pt.y_, *p_pt.y_, *c.curve_p_, t2)) {
      return false;
    }
    if (!big_mod_div(t2, t1, *c.curve_p_, m)) {
      return false;
    }
  } else {
    if (!big_mod_add(*p_pt.y_, *q_pt.y_, *c.curve_p_, t1)) {
      return false;
    }
    if (t1.is_zero()) {
      r_pt.make_zero();
      return true;
    }
    if (!big_mod_mult(*p_pt.x_, *p_pt.x_, *c.curve_p_, t3)) {
      return false;
    }
    if (!big_mod_mult(big_three, t3, *c.curve_p_, t2)) {
      return false;
    }
    t3.zero_num();
    if (!big_mod_add(t2, *c.curve_a_, *c.curve_p_, t3)) {
      return false;
    }
    if (!big_mod_div(t3, t1, *c.curve_p_, m)) {
      return false;
    }
  }

  t1.zero_num();
  t2.zero_num();
  if (!big_mod_mult(m, m, *c.curve_p_, t1)) {
    return false;
  }
  if (!big_mod_sub(t1, *p_pt.x_, *c.curve_p_, t2)) {
    return false;
  }
  if (!big_mod_sub(t2, *q_pt.x_, *c.curve_p_, *r_pt.x_)) {
    return false;
  }
  t1.zero_num();
  t2.zero_num();
  t3.zero_num();
  if (!big_mod_sub(*p_pt.x_, *r_pt.x_, *c.curve_p_, t1)) {
    return false;
  }
  if (!big_mod_mult(m, t1, *c.curve_p_, t2)) {
    return false;
  }
  if (!big_mod_sub(t2, *p_pt.y_, *c.curve_p_, *r_pt.y_)) {
    return false;
  }
  return true;
}

bool ecc_sub(ecc_curve& c, curve_point& p_pt, curve_point& q_pt, curve_point& r_pt) {
  if (q_pt.is_zero()) {
    r_pt.copy_from(p_pt);
    return true;
  }

  curve_point minus_q_pt(q_pt);
  big_num t(2 * c.curve_p_->capacity_);
  if (!big_sub(*c.curve_p_, *q_pt.y_, t)) {
    return false;
  }
  if (!big_mod_normalize(t, *c.curve_p_)) {
    return false;
  }
  minus_q_pt.y_->copy_from(t);
  return ecc_add(c, p_pt, minus_q_pt, r_pt);
}

bool ecc_double(ecc_curve& c, curve_point& p_pt, curve_point& r_pt) {
  return ecc_add(c, p_pt, p_pt, r_pt);
}

//  For Jacobian projective coordinates, see hyperellitptic.org

//  From Cohen, Miyaka, Ono
//  projective addition
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
  big_num x(1 + 2 * c.curve_p_->size_);
  big_num y(1 + 2 * c.curve_p_->size_);
  big_num zinv(1 + 2 * c.curve_p_->size_);

  if (pt.z_->is_zero()) {
    pt.make_zero();
    return true;
  }

  if (pt.z_->is_one())
    return true;
  if (!big_mod_inv(*pt.z_, *c.curve_p_, zinv)) {
    return false;
  }
  if (!big_mod_mult(*pt.x_, zinv, *c.curve_p_, x)) {
    return false;
  }
  if (!big_mod_mult(*pt.y_, zinv, *c.curve_p_, y)) {
    return false;
  }
  if (!big_mod_normalize(x, *c.curve_p_))
    return false;
  if (!big_mod_normalize(y, *c.curve_p_))
    return false;
  if (!pt.x_->copy_from(x))
    return false;
  if (!pt.y_->copy_from(y))
    return false;
  if (!pt.z_->copy_from(big_one))
    return false;
  return true;
}

bool projective_add(ecc_curve& c, curve_point& p_pt, curve_point& q_pt, curve_point& r_pt) {
  big_num u(1 + 2 * c.curve_p_->size_);
  big_num v(1 + 2 * c.curve_p_->size_);
  big_num A(1 + 2 * c.curve_p_->size_);
  big_num u_squared(1 + 2 * c.curve_p_->size_);
  big_num v_squared(1 + 2 * c.curve_p_->size_);
  big_num w(1 + 2 * c.curve_p_->size_);
  big_num t(1 + 2 * c.curve_p_->size_);
  big_num t1(1 + 2 * c.curve_p_->size_);
  big_num t2(1 + 2 * c.curve_p_->size_);
  big_num t3(1 + 2 * c.curve_p_->size_);
  big_num t4(1 + 2 * c.curve_p_->size_);
  big_num a1(1 + 2 * c.curve_p_->size_);
  big_num a2(1 + 2 * c.curve_p_->size_);
  big_num b1(1 + 2 * c.curve_p_->size_);
  big_num b2(1 + 2 * c.curve_p_->size_);

  // If p_pt=O, q_pt
  if (p_pt.z_->is_zero()) {
    r_pt.copy_from(q_pt);
    return true;
  }
  // If q_pt=O, p_pt
  if (q_pt.z_->is_zero()) {
    r_pt.copy_from(p_pt);
    return true;
  }
  if (!big_mod_mult(*p_pt.x_, *q_pt.z_, *c.curve_p_, a1)) {
    return false;
  }
  if (!big_mod_mult(*p_pt.y_, *q_pt.z_, *c.curve_p_, a2)) {
    return false;
  }
  if (!big_mod_mult(*q_pt.x_, *p_pt.z_, *c.curve_p_, b1)) {
    return false;
  }
  if (!big_mod_mult(*q_pt.y_, *p_pt.z_, *c.curve_p_, b2)) {
    return false;
  }

  // If p_pt= q_pt, use doubling
  if (big_compare(a1, b1) == 0) {
    if (big_compare(a2, b2) == 0) return projective_double(c, p_pt, r_pt);
    if (!big_mod_add(a2, b2, *c.curve_p_, t)) {
      return false;
    }
    if (t.is_zero()) {
      r_pt.make_zero();
      return true;
    }
  }

  // u= y2z1-y1z2
  if (!big_mod_mult(*q_pt.y_, *p_pt.z_, *c.curve_p_, t)) {
    return false;
  }
  if (!big_mod_mult(*p_pt.y_, *q_pt.z_, *c.curve_p_, w)) {
    return false;
  }
  if (!big_mod_sub(t, w, *c.curve_p_, u)) {
    return false;
  }
  // v=x2z1-x1z2
  if (!big_mod_mult(*q_pt.x_, *p_pt.z_, *c.curve_p_, t)) {
    return false;
  }
  if (!big_mod_mult(*p_pt.x_, *q_pt.z_, *c.curve_p_, w)) {
    return false;
  }
  if (!big_mod_sub(t, w, *c.curve_p_, v)) {
    return false;
  }
  // A= u^2z1z2-v^3-2v^2x1z2
  if (!big_mod_mult(u, u, *c.curve_p_, u_squared)) {
    return false;
  }
  if (!big_mod_mult(v, v, *c.curve_p_, v_squared)) {
    return false;
  }
  if (!big_mod_mult(u_squared, *p_pt.z_, *c.curve_p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, *q_pt.z_, *c.curve_p_, t1)) {
    return false;
  }
  if (!big_mod_mult(v_squared, v, *c.curve_p_, t2)) {
    return false;
  }
  if (!big_mod_mult(v_squared, *p_pt.x_, *c.curve_p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, *q_pt.z_, *c.curve_p_, t4)) {
    return false;
  }
  if (!big_shift(t4, 1, t3)) {
    return false;
  }
  big_mod_normalize(t3, *c.curve_p_);
  t.zero_num();
  if (!big_mod_sub(t1, t2, *c.curve_p_, t)) {
    return false;
  }
  if (!big_mod_sub(t, t3, *c.curve_p_, A)) {
    return false;
  }
  // x3= vA
  if (!big_mod_mult(v, A, *c.curve_p_, *r_pt.x_)) {
    return false;
  }
  // z3= v^3z1z2
  if (!big_mod_mult(*p_pt.z_, *q_pt.z_, *c.curve_p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, t2, *c.curve_p_, *r_pt.z_)) {
    return false;
  }
  // y3= u(v^2x1z2-A)-v^3y1z2
  t.zero_num();
  if (!big_mod_sub(t4, A, *c.curve_p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, u, *c.curve_p_, w)) {
    return false;
  }
  if (!big_mod_mult(t2, *p_pt.y_, *c.curve_p_, t)) {
    return false;
  }
  if (!big_mod_mult(t, *q_pt.z_, *c.curve_p_, t4)) {
    return false;
  }
  if (!big_mod_sub(w, t4, *c.curve_p_, *r_pt.y_)) {
    return false;
  }
  return true;
}

bool projective_double(ecc_curve& c, curve_point& p_pt, curve_point& r_pt) {
  big_num w(1 + 2 * c.curve_p_->size_);
  big_num w_squared(1 + 2 * c.curve_p_->size_);
  big_num s(1 + 2 * c.curve_p_->size_);
  big_num s_squared(1 + 2 * c.curve_p_->size_);
  big_num h(1 + 2 * c.curve_p_->size_);
  big_num B(1 + 2 * c.curve_p_->size_);
  big_num t1(1 + 2 * c.curve_p_->size_);
  big_num t2(1 + 2 * c.curve_p_->size_);
  big_num t3(1 + 2 * c.curve_p_->size_);
  big_num z1_squared(1 + 2 * c.curve_p_->size_);
  big_num x1_squared(1 + 2 * c.curve_p_->size_);
  big_num y1_squared(1 + 2 * c.curve_p_->size_);

  // w=az1^2+3x1^2
  if (!big_mod_mult(*p_pt.z_, *p_pt.z_, *c.curve_p_, z1_squared)) {
    return false;
  }
  if (!big_mod_mult(*p_pt.x_, *p_pt.x_, *c.curve_p_, x1_squared)) {
    return false;
  }
  if (!big_mod_mult(*c.curve_a_, z1_squared, *c.curve_p_, t1)) {
    return false;
  }
  if (!big_mod_mult(big_three, x1_squared, *c.curve_p_, t2)) {
    return false;
  }
  if (!big_mod_add(t1, t2, *c.curve_p_, w)) {
    return false;
  }
  // s=y1z1
  if (!big_mod_mult(*p_pt.y_, *p_pt.z_, *c.curve_p_, s)) {
    return false;
  }
  // B= x1y1s
  if (!big_mod_mult(*p_pt.x_, *p_pt.y_, *c.curve_p_, t1)) {
    return false;
  }
  if (!big_mod_mult(s, t1, *c.curve_p_, B)) {
    return false;
  }
  // h= w^2-8B
  if (!big_mod_mult(w, w, *c.curve_p_, w_squared)) {
    return false;
  }
  t1.zero_num();
  if (!big_shift(B, 3, t1)) {
    return false;
  }
  big_mod_normalize(t1, *c.curve_p_);
  if (!big_mod_sub(w_squared, t1, *c.curve_p_, h)) {
    return false;
  }

  // x3=2hs
  t1.zero_num();
  if (!big_mod_mult(h, s, *c.curve_p_, t1)) {
    return false;
  }
  t2.zero_num();
  if (!big_shift(t1, 1, t2)) {
    return false;
  }
  big_mod_normalize(t2, *c.curve_p_);
  r_pt.x_->copy_from(t2);

  // z3= 8s^3
  if (!big_mod_mult(s, s, *c.curve_p_, s_squared)) {
    return false;
  }
  if (!big_mod_mult(s_squared, s, *c.curve_p_, t1)) {
    return false;
  }
  t2.zero_num();
  if (!big_shift(t1, 3, t2)) {
    return false;
  }
  big_mod_normalize(t2, *c.curve_p_);
  r_pt.z_->copy_from(t2);

  // y3= w(4B-h) -8y1^2s^2
  if (!big_mod_mult(*p_pt.y_, *p_pt.y_, *c.curve_p_, y1_squared)) {
    return false;
  }
  t1.zero_num();
  t2.zero_num();
  if (!big_shift(B, 2, t1)) {
    return false;
  }
  big_mod_normalize(t1, *c.curve_p_);
  if (!big_mod_sub(t1, h, *c.curve_p_, t2)) {
    return false;
  }
  t1.zero_num();
  if (!big_mod_mult(w, t2, *c.curve_p_, t1)) {
    return false;
  }
  if (!big_mod_mult(s_squared, y1_squared, *c.curve_p_, t2)) {
    return false;
  }
  if (!big_shift(t2, 3, t3)) {
    return false;
  }
  big_mod_normalize(t3, *c.curve_p_);
  if (!big_mod_sub(t1, t3, *c.curve_p_, *r_pt.y_)) {
    return false;
  }
  return true;
}

bool projective_point_mult(ecc_curve& c, big_num& x, curve_point& p_pt, curve_point& r_pt) {
  if (x.is_zero()) {
    r_pt.make_zero();
    return true;
  }
  if (x.is_one()) {
    return r_pt.copy_from(p_pt);
  }
  if (p_pt.z_->is_zero()) {
    r_pt.make_zero();
    return true;
  }

  int k = big_high_bit(x);
  int i;
  curve_point double_point(p_pt, 1 + 2 * c.curve_p_->capacity_);
  curve_point accum_point(1 + 2 * c.curve_p_->capacity_);
  curve_point t1(1 + 2 * c.curve_p_->capacity_);

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

bool ecc_mult(ecc_curve& c, curve_point& p_pt, big_num& x, curve_point& r_pt) {
  if (x.is_zero()) {
    r_pt.make_zero();
    return true;
  }
  if (x.is_one()) {
    return r_pt.copy_from(p_pt);
  }
  int k = big_high_bit(x);
  int i;
  curve_point double_point(p_pt, 1 + 2 * c.curve_p_->capacity_);
  curve_point accum_point(1 + 2 * c.curve_p_->capacity_);
  curve_point t1(1 + 2 * c.curve_p_->capacity_);

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

bool faster_ecc_mult(ecc_curve& c, curve_point& p_pt, big_num& x, curve_point& r_pt) {
  if (x.is_zero()) {
    r_pt.make_zero();
    return true;
  }
  if (x.is_one()) {
    return r_pt.copy_from(p_pt);
  }
  if (!projective_point_mult(c, x, p_pt, r_pt)) {
    return false;
  }
  if (!projective_to_affine(c, r_pt)) {
    return false;
  }
  if (x.is_negative()) {
    r_pt.y_->toggle_sign();
  }
  return true;
}

ecc::ecc() {
  initialized_ = false;
  ecc_key_ = nullptr;
  prime_bit_size_ = 0;
  c_ = nullptr;
  order_of_base_point_ = nullptr;
  base_point_ = nullptr;
  public_point_ = nullptr;
  secret_ = nullptr;
}

ecc::~ecc() {
  if (ecc_key_ != nullptr) {
    delete ecc_key_;
    ecc_key_ = nullptr;
  }
  if (c_ != nullptr) {
    delete c_;
    c_ = nullptr;
  }
  if (base_point_ != nullptr) {
    delete base_point_;
    base_point_ = nullptr;
  }
  if (order_of_base_point_ != nullptr) {
    delete order_of_base_point_;
    order_of_base_point_ = nullptr;
  }
  if (public_point_ != nullptr) {
    delete public_point_;
    public_point_ = nullptr;
  }
  if (secret_ != nullptr) {
    delete secret_;
    secret_ = nullptr;
  }
}

bool ecc::copy_key_parameters_from(ecc& copy_key) {
  if (copy_key.c_ == nullptr || copy_key.base_point_ == nullptr)
    return false;
  prime_bit_size_ = copy_key.prime_bit_size_;
  int nw = 1 + prime_bit_size_ / (NBITSINBYTE * sizeof(uint64_t));

  if (copy_key.c_ != nullptr) {
    if (c_ == nullptr) {
      c_= new ecc_curve(nw);
      if (c_ == nullptr)
        return false;
    }
    c_->copy_from(*copy_key.c_);
  }
  not_before_.assign(copy_key.not_before_);
  not_after_.assign(copy_key.not_after_);

  if (copy_key.base_point_ != nullptr) {
    if (base_point_ == nullptr) {
      base_point_ = new curve_point(nw);
      if (base_point_ == nullptr)
        return false;
    }
    base_point_->copy_from(*copy_key.base_point_); // curve_point
  }

  if (copy_key.order_of_base_point_ != nullptr) {
    if (order_of_base_point_ != nullptr)
      order_of_base_point_->copy_from(*copy_key.order_of_base_point_);
    if (base_point_ != nullptr)
      base_point_->copy_from(*copy_key.base_point_);  // base_point = base_point * secret
  }

  if (copy_key.secret_ != nullptr) {
    if (secret_ == nullptr) {
      secret_ = new big_num(nw);
      if (secret_ == nullptr)
        return false;
    }
    secret_->copy_from(*copy_key.secret_);
  }
  initialized_ = copy_key.initialized_;

  return true;
}

bool ecc::generate_ecc_from_parameters(const char* key_name, const char* usage,
        char* notbefore, char* notafter, double seconds_to_live, ecc_curve& c,
        curve_point& base_pt, big_num& order_base_point, big_num& secret) {
  initialized_ = false;

  prime_bit_size_ = c.prime_bit_size_;
  not_before_.assign(notbefore);
  not_after_.assign(notafter);
  int nw = 1 + prime_bit_size_ / (NBITSINBYTE * sizeof(uint64_t));
  c_ = new ecc_curve(nw);
  c_->copy_from(c);
  base_point_ = new curve_point(nw);
  base_point_->copy_from(base_pt);
  order_of_base_point_= new big_num(nw);
  order_of_base_point_->copy_from(order_base_point);
  public_point_ = new curve_point(nw);  // public_point = public_point * secret
  secret_ = new big_num(nw);
  secret.copy_to(*secret_);
  if (base_point_ == nullptr) {
    base_point_ = new curve_point(nw);
  }
  if (!ecc_mult(*c_, *base_point_, *secret_, *public_point_))
    return false;

  string s_curve_p;
  string s_curve_a;
  string s_curve_b;
  string s_base_order;
  string s_secret;
  string s_curve_base_x;
  string s_curve_base_y;
  string s_curve_public_x;
  string s_curve_public_y;

  if (!bignum_to_string_msg(*secret_, &s_secret))
    return false;
  if (!bignum_to_string_msg(*c.curve_p_, &s_curve_p))
    return false;
  if (!bignum_to_string_msg(*c.curve_a_, &s_curve_a))
    return false;
  if (!bignum_to_string_msg(*c.curve_b_, &s_curve_b))
    return false;
  if (!bignum_to_string_msg(order_base_point, &s_base_order))
    return false;
  if (!bignum_to_string_msg(*base_pt.x_, &s_curve_base_x))
    return false;
  if (!bignum_to_string_msg(*base_pt.y_, &s_curve_base_y))
    return false;
  if (!bignum_to_string_msg(*public_point_->x_, &s_curve_public_x))
    return false;
  if (!bignum_to_string_msg(*public_point_->y_, &s_curve_public_y))
    return false;
  
  key_message* new_key_message =  make_ecckey(key_name, prime_bit_size_, usage,
         notbefore, notafter, c.c_name_, s_curve_p, s_curve_a, s_curve_b,
         s_curve_base_x, s_curve_base_y, s_base_order, s_secret,
         s_curve_public_x, s_curve_public_y);
  if (new_key_message == nullptr)
    return false;
  if (ecc_key_ != nullptr)
    delete ecc_key_;
  ecc_key_ = new_key_message;
  initialized_ = true;
  return initialized_;
}

bool ecc::generate_ecc_from_standard_template(const char* template_name, const char* key_name,
          const char* usage, double seconds_to_live) {
  if (template_name == nullptr)
    return true;

  if (!init_ecc_curves()) {
    printf("init_ecc_curves failed\n");
    return false;
  }

  // find template
  int nb = 0;
  ecc* key_to_copy = nullptr;
  if (template_name == nullptr || strlen(template_name) < 1)
    return false;
  if (strcmp(template_name, "P-256") == 0) {
    // use p256_key
    nb = 32;
    if (!copy_key_parameters_from(p256_key))
      return false;
    key_to_copy = &p256_key;
  } else if (strcmp(template_name, "P-384") == 0) {
    // use p384_key
    nb = 48;
    if (!copy_key_parameters_from(p384_key))
      return false;
    key_to_copy = &p384_key;
  } else if (strcmp(template_name, "P-521") == 0) {
    key_to_copy = &p521_key;
    if (!copy_key_parameters_from(p521_key))
      return false;
    nb = 64;
  } else {
    return false;
  }

  if (key_to_copy->c_ == nullptr || key_to_copy->order_of_base_point_ == nullptr ||
        key_to_copy->base_point_ == nullptr)
    return false;

  string notbefore;
  string notafter;

  time_point t1;
  time_point t2;

  if (!t1.time_now())
    return false;
  if (!t2.add_interval_to_time(t1, seconds_to_live))
    return false;
  if (!t1.encode_time(&notbefore))
    return false;
  if (!t2.encode_time(&notafter))
    return false;

  byte byte_secret[nb];
  if (crypto_get_random_bytes(nb, byte_secret) < 0) {
    printf("Cant generate random bits for ecc key\n");
    return false;
  }

  int n_u64 = (nb / sizeof(uint64_t));
  big_num big_num_secret(n_u64);
  memcpy((byte*)big_num_secret.value_ptr(), byte_secret, nb);
  big_num_secret.normalize();
  
  return generate_ecc_from_parameters(key_name, usage, (char*)notbefore.c_str(),
           (char*)notafter.c_str(), seconds_to_live, *key_to_copy->c_, *key_to_copy->base_point_,
           *key_to_copy->order_of_base_point_, big_num_secret);
}

bool ecc::get_serialized_key_message(string* s) {
  if (ecc_key_ == nullptr)
    return false;
  ecc_key_->SerializeToString(s);
  return true;
}

bool ecc::set_parameters_in_key_message() {
  if (ecc_key_ == nullptr) {
    ecc_key_ = new key_message;
    if (ecc_key_ == nullptr) {
      return false;
    }
  }
  ecc_key_->set_family_type("public");
  ecc_key_->set_algorithm_type("ecc");

  ecc_key_->set_notbefore(not_before_);
  ecc_key_->set_notafter(not_after_);

  string s;

  ecc_private_parameters_message* ecc_priv = ecc_key_->mutable_ecc_priv();
 
  if (secret_ != nullptr) { 
    s.clear();
    if(!bignum_to_string_msg(*secret_, &s)) {
      return false;
    }
    ecc_priv->set_private_multiplier(s);
  }
  ecc_public_parameters_message* ecc_pub = ecc_key_->mutable_ecc_pub();
  curve_message* cm = ecc_pub->mutable_cm();
  if (c_ == nullptr || c_->curve_p_ == nullptr ||
      c_->curve_a_ == nullptr || c_->curve_b_ == nullptr)
    return false;
  ecc_key_->set_key_size(c_->prime_bit_size_);
  cm->set_curve_name(c_->c_name_);

  s.clear();
  if(!bignum_to_string_msg(*c_->curve_p_, &s)) {
    return false;
  }
  cm->set_curve_p(s);
  s.clear();
  if(!bignum_to_string_msg(*c_->curve_a_, &s)) {
    return false;
  }
  cm->set_curve_a(s);
  s.clear();
  if(!bignum_to_string_msg(*c_->curve_b_, &s)) {
    return false;
  }
  cm->set_curve_b(s);

  point_message* pm = ecc_pub->mutable_base_point();
  if (base_point_ != nullptr) {
    if (base_point_->x_ != nullptr) {
      s.clear();
      if(!bignum_to_string_msg(*base_point_->x_, &s)) {
        return false;
      }
      pm->set_x(s);
    }
    if (base_point_->y_ != nullptr) {
      s.clear();
      if(!bignum_to_string_msg(*base_point_->y_, &s)) {
        return false;
      }
      pm->set_y(s);
    }
  }

  pm = ecc_pub->mutable_public_point();
  if (public_point_ != nullptr) {
    if (public_point_->x_ != nullptr) {
      s.clear();
      if(!bignum_to_string_msg(*public_point_->x_, &s)) {
        return false;
      }
      pm->set_x(s);
    }
    if (public_point_->y_ != nullptr) {
      s.clear();
      if(!bignum_to_string_msg(*public_point_->y_, &s)) {
        return false;
      }
      pm->set_y(s);
    }
  }

  if (order_of_base_point_ != nullptr) { 
    s.clear();
    if(!bignum_to_string_msg(*order_of_base_point_, &s)) {
      return false;
    }
    ecc_pub->set_order_of_base_point(s);
  }

  return true;
}

/*
  optional string family_type
  optional string algorithm_type
  optional string key_name
  optional int32 key_size
  optional string purpose
  optional string notBefore
  optional string notAfter
  optional ecc_public_parameters_message ecc_pub
      optional curve_message cm
          optional string curve_name
          optional bytes curve_p
          optional bytes curve_a
          optional bytes curve_b
      optional point_message base_point
      optional point_message public_point
      optional bytes order_of_base_point
  optional ecc_private_parameters_message ecc_priv
    optional bytes private_multiplier
 */
bool ecc::retrieve_parameters_from_key_message() {
  if (ecc_key_ == nullptr)
    return false;

  if (!ecc_key_->has_key_size()) {
    return false;
  }
  prime_bit_size_ = ecc_key_->key_size();
  if(ecc_key_->has_notafter()) {
    not_after_.assign(ecc_key_->notafter());
  }
  if(ecc_key_->has_notbefore()) {
    not_before_.assign(ecc_key_->notbefore());
  }

  int u64_size = 1 + (prime_bit_size_ / (NBITSINBYTE * sizeof(uint64_t)));

  if (ecc_key_->has_ecc_pub()) {
    ecc_public_parameters_message* pub = ecc_key_->mutable_ecc_pub();
    if(pub->has_cm()) {
      curve_message* cmsg = pub->mutable_cm();
      if (c_ != nullptr && c_->prime_bit_size_ < prime_bit_size_)  {
        delete c_;
        c_ = nullptr;
      }
      if (c_ == nullptr) {
        c_ = new ecc_curve(u64_size);
        if (c_ == nullptr)
          return false;
      }
      if (cmsg->has_curve_name()) {
        c_->c_name_.assign(cmsg->curve_name());
      }
      if (cmsg->has_curve_p()) {
        if (c_->curve_p_ == nullptr) {
          c_->curve_p_ = new big_num(u64_size);
          if (c_->curve_p_ == nullptr)
            return false;
        }
        big_num* p = c_->curve_p_;
        if(!string_msg_to_bignum(cmsg->curve_p(), *p))
          return false;
      }
      if (cmsg->has_curve_a()) {
        if (c_->curve_a_ == nullptr) {
          c_->curve_a_ = new big_num(u64_size);
          if (c_->curve_a_ == nullptr)
            return false;
        }
        big_num* a = c_->curve_a_;
        if(!string_msg_to_bignum(cmsg->curve_a(), *a))
          return false;
      }
      if (cmsg->has_curve_b()) {
        if (c_->curve_b_ == nullptr) {
          c_->curve_b_ = new big_num(u64_size);
          if (c_->curve_b_ == nullptr)
            return false;
        }
        big_num* b = c_->curve_b_;
        if(!string_msg_to_bignum(cmsg->curve_b(), *b))
          return false;
      }
    }
    if (pub->has_order_of_base_point()) {
      if (order_of_base_point_ == nullptr) {
        order_of_base_point_ = new big_num(u64_size);
        if (order_of_base_point_ == nullptr)
          return false;
      }
      if(!string_msg_to_bignum(pub->order_of_base_point(), *order_of_base_point_))
          return false;
    }
    if (pub->has_base_point()) {
      point_message* pm = pub->mutable_base_point();
      if (base_point_ == nullptr) {
        base_point_= new curve_point(u64_size);
        if (base_point_ == nullptr)
          return false;
      }
      if (pm->has_x()) {
        if (base_point_->x_ == nullptr) {
          base_point_->x_ = new big_num(u64_size);
          if (base_point_->x_ == nullptr)
            return false;
        }
        if(!string_msg_to_bignum(pm->x(), *base_point_->x_))
            return false;
      }
      if (pm->has_y()) {
        if (base_point_->y_ == nullptr) {
          base_point_->y_ = new big_num(u64_size);
          if (base_point_->y_ == nullptr)
            return false;
        }
        if(!string_msg_to_bignum(pm->y(), *base_point_->y_))
            return false;
      }
    }
    if (pub->has_public_point()) {
      point_message* pm = pub->mutable_public_point();

      if (public_point_ == nullptr) {
        public_point_= new curve_point(u64_size);
        if (public_point_ == nullptr)
          return false;
      }
      if (pm->has_x()) {
        if (public_point_->x_ == nullptr) {
          public_point_->x_ = new big_num(u64_size);
          if (public_point_->x_ == nullptr)
            return false;
        }
        if(!string_msg_to_bignum(pm->x(), *public_point_->x_))
            return false;
      }
      if (pm->has_y()) {
        if (public_point_->y_ == nullptr) {
          public_point_->y_ = new big_num(u64_size);
          if (public_point_->y_ == nullptr)
            return false;
        }
        if(!string_msg_to_bignum(pm->y(), *public_point_->y_))
            return false;
      }
    }
  }

  if (ecc_key_->has_ecc_priv()) {
    ecc_private_parameters_message* priv = ecc_key_->mutable_ecc_priv();

    if (priv->has_private_multiplier()) {
      if (secret_ == nullptr) {
          secret_ = new big_num(u64_size);
          if (secret_ == nullptr)
            return false;
        }
        if(!string_msg_to_bignum(priv->private_multiplier(), *secret_))
            return false;
    }
  }

  return true;
}

bool ecc::extract_key_message_from_serialized(string& s) {
  if (ecc_key_== nullptr) {
    ecc_key_= new key_message;
    if (ecc_key_== nullptr)
      return false;
  }
  ecc_key_->ParseFromString(s);
  return true;
}

void ecc::print() {
  printf("\necc key:\n");
  printf("modulus size: %d bits\n", prime_bit_size_);
  if (c_ == nullptr)
    return;
  c_->print_curve();
  printf("Not before: %s\n", not_before_.c_str());
  printf("Not after: %s\n", not_after_.c_str());
  if (base_point_ != nullptr) {
    printf("base: "); base_point_->print(); printf("\n");
  }
  if (order_of_base_point_ != nullptr) {
    printf("order base point: "); order_of_base_point_->print(); printf("\n");
  }
  if (secret_ != nullptr) {
    printf("secret: "); secret_->print(); printf("\n");
  }
  if (public_point_ != nullptr) {
    printf("public: "); public_point_->print(); printf("\n");
  }
  printf("\n");
}

//  embed message into point M
//  pick k at random
//  send (kG, kBase+M)
bool ecc::encrypt(int size, byte* plain, big_num& k, curve_point& pt1,
                     curve_point& pt2) {
  if (c_ == nullptr)
    return false;
  big_num m(c_->curve_p_->capacity_);
  curve_point p_pt(c_->curve_p_->capacity_);
  curve_point r_pt(c_->curve_p_->capacity_);

  memcpy((byte*)m.value_, plain, size);
  m.normalize();
  if (!ecc_embed(*c_, m, p_pt, 8, 20)) {
    return false;
  }
#ifdef FASTECCMULT
  if (!faster_ecc_mult(*c_, *base_point_, k, pt1)) {
    return false;
  }
  if (!faster_ecc_mult(*c_, *public_point_, k, r_pt)) {
    return false;
  }
#else
  if (!ecc_mult(*c_, *base_point_, k, pt1)) {
    return false;
  }
  if (!ecc_mult(*c_, *public_point_, k, r_pt)) {
    return false;
  }
#endif
  if (!ecc_add(*c_, r_pt, p_pt, pt2)) {
    return false;
  }
  return true;
}

bool ecc::decrypt(curve_point& pt1, curve_point& pt2, int* size, byte* plain) {
  if (c_ == nullptr)
    return false;

  big_num m(c_->curve_p_->capacity_);
  curve_point p_pt(c_->curve_p_->capacity_);
  curve_point r_pt(c_->curve_p_->capacity_);

#ifdef FASTECCMULT
  if (!faster_ecc_mult(*c_, pt1, *(secret_), r_pt)) {
    return false;
  }
#else
  if (!ecc_mult(*c_, pt1, *(secret_), r_pt)) {
    return false;
  }
#endif
  if (!ecc_sub(*c_, pt2, r_pt, p_pt)) {
    return false;
  }
  if (!ecc_extract(*c_, p_pt, m, 8)) {
    return false;
  }
  m.normalize();
  *size = m.size() * sizeof(uint64_t);
  memcpy(plain, (byte*)m.value_, *size);
  return true;
}
