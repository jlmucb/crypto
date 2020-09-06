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

bool test_ecc1() {
  // bool ecc_add(ecc_curve& c, curve_point& p_pt, curve_point& q_pt, curve_point& r_pt);
  // bool ecc_sub(ecc_curve& c, curve_point& p_pt, curve_point& q_pt, curve_point& r_pt);
  // bool ecc_double(ecc_curve& c, curve_point& p_pt, curve_point& r_pt);
  // bool ecc_mult(ecc_curve& c, curve_point& p_pt, big_num& x, curve_point& r_pt);
  // bool faster_ecc_mult(ecc_curve& c, curve_point& p_pt, big_num& x, curve_point& r_pt);
  return true;
}

bool test_ecc2() {
  // bool ecc_embed(ecc_curve& c, big_num& m, curve_point& pt, int shift, int trys);
  // bool ecc_extract(ecc_curve& c, curve_point& pt, big_num& m, int shift);
  // bool ecc_normalize(ecc_curve& c, curve_point& pt);
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

TEST (ecc, test_ecc_basic) {
  EXPECT_TRUE(test_ecc1());
  EXPECT_TRUE(test_ecc2());
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
