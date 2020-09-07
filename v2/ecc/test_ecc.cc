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
// File: test_ecc.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "big_num.h"
#include "big_num_functions.h"
#include "ecc.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");

// E: y^2 = y^3 +4x+4 (mod 2773)
//  2(1,3) = (1771,705)
//  (7,23) + (2,145) = (2472, 837)
bool test_ecc_affine_1() {
  ecc_curve c1(1);
  c1.curve_p_->value_[0] = 2773;
  c1.curve_a_->value_[0] = 4;
  c1.curve_b_->value_[0] = 4;
  curve_point p1(1);
  curve_point p2(1);
  curve_point p3(2);
  curve_point p4(2);
  curve_point p5(2);

  printf("curve:\n");
  c1.print_curve();

  p1.x_->zero_num();
  p1.y_->zero_num();
  p2.x_->zero_num();
  p2.y_->zero_num();
  p3.x_->zero_num();
  p3.y_->zero_num();
  p4.x_->zero_num();
  p4.y_->zero_num();
  p5.x_->zero_num();
  p5.y_->zero_num();

  p1.x_->value_[0] = 1;
  p1.y_->value_[0] = 3;
  p2.x_->value_[0] = 2;
  p2.y_->value_[0] = 23;
  p3.x_->value_[0] = 7;
  p3.y_->value_[0] = 145;

  p1.x_->normalize();
  p1.y_->normalize();
  p2.x_->normalize();
  p2.y_->normalize();
  p3.x_->normalize();
  p3.y_->normalize();
  if (!ecc_add(c1, p2, p3, p4))
    return false;
  // (2472, 715)
  if (FLAGS_print_all) {
    printf("  (%lld, %lld)", p2.x_->value_[0], p2.y_->value_[0]);
    printf(" + ");
    printf("(%lld, %lld)", p3.x_->value_[0], p3.y_->value_[0]);
    printf("= (%lld, %lld)\n", p4.x_->value_[0], p4.y_->value_[0]);
  }
  if (p4.x_->value_[0] != 2472 || p4.y_->value_[0] !=715)
    return false;

  // (1771, 705)
  if (!ecc_mult(c1, p1, big_two, p5))
    return false;
  if (FLAGS_print_all) {
    printf("  2 * (%lld, %lld) = (%lld, %lld)\n", p1.x_->value_[0], p1.y_->value_[0],
        p5.x_->value_[0], p5.y_->value_[0]);
  }
  if (p5.x_->value_[0] != 1771 || p5.y_->value_[0] != 705)
    return false;
  p5.clear();

  if (!ecc_sub(c1, p4, p2, p5))
    return false;
  if (!p5.is_equal(p3))
    return false;

  p4.clear();
  p5.clear();
  if (!ecc_sub(c1, p1, p1, p4))
    return false;
  if (!p4.is_zero())
  if (FLAGS_print_all) {
    printf("  (%lld, %lld)", p1.x_->value_[0], p1.y_->value_[0]);
    printf(" - ");
    printf("(%lld, %lld)", p1.x_->value_[0], p1.y_->value_[0]);
    printf("= (%lld, %lld, %lld)\n", p4.x_->value_[0], p4.y_->value_[0],
          p4.z_->value_[0]);
  }
  if (!p4.is_zero())
    return false;

  p5.clear();
  if (!ecc_double(c1, p1, p5))
    return false;
  if (p5.x_->value_[0] != 1771 || p5.y_->value_[0] != 705)
    return false;

  return true;
}

bool test_ecc_affine_2() {
  // bool ecc_embed(ecc_curve& c, big_num& m, curve_point& pt, int shift, int trys);
  // bool ecc_extract(ecc_curve& c, curve_point& pt, big_num& m, int shift);
  // bool ecc_normalize(ecc_curve& c, curve_point& pt);
  return true;
}

bool test_ecc_projective() {
  // bool projective_to_affine(ecc_curve& c, curve_point& pt);
  // bool projective_add(ecc_curve& c, curve_point& p_pt, curve_point& q_pt, curve_point& r_pt);
  // bool projective_double(ecc_curve& c, curve_point& p_pt, curve_point& r_pt);
  // bool projective_point_mult(ecc_curve& c, big_num& x, curve_point& p_pt, curve_point& r_pt);
/*
  p5.clear();
  if (!faster_ecc_mult(c1, p1, big_two, p5))
    return false;
  if (p5.x_->value_[0] != 1771 || p5.y_->value_[0] != 705)
    return false;
*/
  return true;
}

bool test_ecc_curve_point() {
  // bool is_zero();
  // void clear();
  // void make_zero();
  // bool copy_from(curve_point& pt);
  // bool copy_to(curve_point& pt);
  // bool normalize(big_num& p);
  // void print();
  return true;
}

bool test_ecc_curve() {
  // void clear();
  // void print_curve();
  // bool copy_from(ecc_curve& c);

  return true;
}

bool test_ecc_class() {
  // bool copy_key_parameters_from(ecc& copy_key);
  // bool get_serialized_key_message(string* s);
  // bool set_parameters_in_key_message();
  // bool retrieve_parameters_from_key_message();
  // bool extract_key_message_from_serialized(string& s);
  // bool generate_ecc(int num_bits);
  // bool generate_ecc_from_parameters(const char* key_name, const char* usage,
  //     char* notbefore, char* notafter, double seconds_to_live, ecc_curve& c,
  //     curve_point& base, curve_point& public_point,
  //     big_num& order_base_point, big_num& secret);
  // bool generate_ecc_from_standard_template(const char* template_name, const char* key_name,
  //      const char* usage, double seconds_to_live);
  // void print();

  return true;
}

bool test_ecc_encrypt_decrypt() {

  //  bool encrypt(int size, byte* plain, big_num& k, curve_point& pt1, curve_point& pt2);
  // bool decrypt(curve_point& pt1, curve_point& pt2, int* size, byte* plain);
  return true;
}

TEST (ecc, test_affine) {
  EXPECT_TRUE(test_ecc_affine_1());
  EXPECT_TRUE(test_ecc_affine_2());
}
TEST (ecc, test_projective) {
  EXPECT_TRUE(test_ecc_projective());
}
TEST (ecc_curve_point, ecc_curve_point) {
  EXPECT_TRUE(test_ecc_curve_point());
}
TEST (ecc_curve, ecc_curve) {
  EXPECT_TRUE(test_ecc_curve());
}
TEST (ecc_class, ecc_class) {
  EXPECT_TRUE(test_ecc_class());
}
TEST (ecc_encrypt, ecc_encrypt) {
  EXPECT_TRUE(test_ecc_encrypt_decrypt());
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!init_crypto()) {
    printf("init_crypto failed\n");
    return 1;
  }

  int result = RUN_ALL_TESTS();

  close_crypto();
  printf("\n");
  return result;
}
