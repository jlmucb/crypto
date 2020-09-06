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
// File: ecc.h

#include "crypto_support.h"
#include "big_num.h"
#include "big_num_functions.h"

// Background
//  The elliptic curve EC(p, a, b) is the set of points (x,y) with y^2= x^3+ax+b
//  plus a point at infinity, denoted by O.  Usually, we assume the right hand
//  side of the equation defining EC(p, a, b) does not have repeated roots.
//  p is an odd prime.
//  To add two points P1 and P2, first check to see if one of them, say, P2 is O,
//  then P1 + P2 = P1.  Otherwise, P1 = (x1, y1) and P2= (x2,y2).
//  Calculate m as follows:
//    If P1 != P2, m = (y2-y1)/(x2-x1).
//    If P1=P2, m= (3x1^2+b)/(2y1).
//  In either case, if denominator used in claculating m is 0, P1+P2=O, otherwise,
//    P3=(x3,y3), x3 = m^2-x1-x2, y3 = m(x1-x3)-y1. All calculations mod p.
//  Hasse: If N is the number of point on EC(p, a, b), |N-p-1| < 2sqrt(p).
//  To embed an n bit  message m in a point, M, shift m by k bits, where
//  n + k > size of p. Denote the shifted message by x.  Check to see if
//  x^3+ax+b is a square, if so, calculate its square root as y.  M=(x,y).
//  If x^3+ax+b is not a square, change the bottom k bits of x until you obtain
//  a square.  To extract a message from (x, y), just shift x k bits.
//
//  ECC
//    Given EC(p, a, b) and a point B on EC(p, a, b), private key holder picks
//    a secret 0 <= sA < p uniformly at random.  Public key is EC(p, a, b), B,
//    P, where P=(secret)B.
//  ECC encrypt
//    Sender picks a secret, sB, 0 <= sB < p.  You should never reuse sB.
//    Sender embeds his message in a point M and calculates (sB)B and (sB)P.
//    Encrypted message is [(sB)B, M+(sB)P].
//  ECC decrypt
//    Receiver gets message D = [Q, R].  He calculates M= R - (sA)Q and extracts
//    m form M.
//  ECC sign(m).  Public, private keys are the same as in ECC.
//    Pick an unreuseable nonce, sS, 0 <= sS < N.  Make sure sS has an inverse
//    mod N.
//    Compute Q= (sS)B = (x,y).
//    Compute s= (sS^(-1))(m-sAx) (mod N).
//    Send [m, Q, s]
//  ECC verify
//    Compute v1 = xB + sQ and v2 = mA.  Accept signature if v1 == v2.

#ifndef _CRYPTO_ECC_H__
#define _CRYPTO_ECC_H__

class curve_point {
 public:
  big_num* x_;
  big_num* y_;
  big_num* z_;

  curve_point();
  curve_point(int size);
  curve_point(big_num& x, big_num& y);
  curve_point(curve_point& pt);
  curve_point(curve_point& pt, int capacity);
  ~curve_point();

  bool is_zero();
  void clear();
  void make_zero();
  bool copy_from(curve_point& pt);
  bool copy_to(curve_point& pt);
  bool normalize(big_num& p);
  void print();
};

class ecc_curve {
 public:
  int prime_bit_size_;
  string c_name_;
  big_num* curve_p_;
  big_num* curve_a_;
  big_num* curve_b_;

  ecc_curve();
  ecc_curve(int size);
  ecc_curve(big_num& a, big_num& b, big_num& p);
  ~ecc_curve();

  void clear();
  void print_curve();
  bool copy_from(ecc_curve& c);
};

class ecc {
 public:
  bool initialized_;
  key_message *ecc_key_;
  int prime_bit_size_;
  ecc_curve* c_;
  string not_before_;
  string not_after_;
  curve_point* base_point_;
  big_num* order_of_base_point_;
  curve_point* public_point_;  // public_point = base_point * secret
  big_num* secret_;
  
  ecc();
  ~ecc(); 

  bool copy_key_parameters_from(ecc& copy_key);
  bool get_serialized_key_message(string* s);
  bool set_parameters_in_key_message();
  bool retrieve_parameters_from_key_message();
  bool extract_key_message_from_serialized(string& s);
  bool generate_ecc(int num_bits);
  bool decrypt(curve_point& pt1, curve_point& pt2, int* size, byte* plain);
  bool generate_ecc_from_parameters(const char* key_name, const char* usage,
        char* notbefore, char* notafter, double seconds_to_live, ecc_curve& c,
        curve_point& base, curve_point& public_point,
        big_num& order_base_point, big_num& secret);
  bool generate_ecc_from_standard_template(const char* template_name, const char* key_name,
          const char* usage, double seconds_to_live);
  bool encrypt(int size, byte* plain, big_num& k, curve_point& pt1, curve_point& pt2);
  void print();
};

bool ecc_embed(ecc_curve& c, big_num& m, curve_point& pt, int shift, int trys);
bool ecc_extract(ecc_curve& c, curve_point& pt, big_num& m, int shift);
bool ecc_normalize(ecc_curve& c, curve_point& pt);
bool ecc_add(ecc_curve& c, curve_point& p_pt, curve_point& q_pt, curve_point& r_pt);
bool ecc_sub(ecc_curve& c, curve_point& p_pt, curve_point& q_pt, curve_point& r_pt);
bool ecc_double(ecc_curve& c, curve_point& p_pt, curve_point& r_pt);
bool ecc_mult(ecc_curve& c, curve_point& p_pt, big_num& x, curve_point& r_pt);
bool faster_ecc_mult(ecc_curve& c, curve_point& p_pt, big_num& x, curve_point& r_pt);
bool projective_to_affine(ecc_curve& c, curve_point& pt);
bool projective_add(ecc_curve& c, curve_point& p_pt, curve_point& q_pt, curve_point& r_pt);
bool projective_double(ecc_curve& c, curve_point& p_pt, curve_point& r_pt);
bool projective_point_multult(ecc_curve& c, big_num& x, curve_point& p_pt, curve_point& r_pt);

#endif
