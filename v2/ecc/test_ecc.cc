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
#include "ecc_curve_data.h"


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
    printf("  (%ld, %ld)", p2.x_->value_[0], p2.y_->value_[0]);
    printf(" + ");
    printf("(%ld, %ld)", p3.x_->value_[0], p3.y_->value_[0]);
    printf("= (%ld, %ld)\n", p4.x_->value_[0], p4.y_->value_[0]);
  }
  if (p4.x_->value_[0] != 2472 || p4.y_->value_[0] !=715)
    return false;

  // (1771, 705)
  if (!ecc_mult(c1, p1, big_two, p5))
    return false;
  if (FLAGS_print_all) {
    printf("  2 * (%ld, %ld) = (%ld, %ld)\n", p1.x_->value_[0], p1.y_->value_[0],
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
    printf("  (%ld, %ld)", p1.x_->value_[0], p1.y_->value_[0]);
    printf(" - ");
    printf("(%ld, %ld)", p1.x_->value_[0], p1.y_->value_[0]);
    printf("= (%ld, %ld, %ld)\n", p4.x_->value_[0], p4.y_->value_[0],
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
  ecc_curve c1(1);
  c1.curve_p_->value_[0] = 2773;
  c1.curve_a_->value_[0] = 4;
  c1.curve_b_->value_[0] = 4;
  c1.curve_p_->normalize();
  c1.curve_a_->normalize();
  c1.curve_b_->normalize();
  curve_point p1(1);
  curve_point p2(1);
  curve_point p3(1);
  curve_point p4(1);
  curve_point p5(2);

  p1.x_->value_[0] = 1;
  p1.x_->normalize();
  p1.y_->value_[0] = 3;
  p1.y_->normalize();
  p1.z_->value_[0] = 1;
  p1.x_->normalize();

  p5.clear();
  if (!faster_ecc_mult(c1, p1, big_two, p5))
    return false;
  if (p5.x_->value_[0] != 1771 || p5.y_->value_[0] != 705)
    return false;

  p2.x_->value_[0] = 2;
  p2.x_->normalize();
  p2.y_->value_[0] = 6;
  p2.y_->normalize();
  p2.z_->value_[0] = 2;
  p2.x_->normalize();
  p5.clear();
  p5.copy_from(p2);

  if (!projective_to_affine(c1, p5))
    return false;
  if (FLAGS_print_all) {
    printf("  (%ld, %ld, %ld) = ", p2.x_->value_[0], p2.y_->value_[0], p2.z_->value_[0]);
    printf("  (%ld, %ld, %ld)\n", p5.x_->value_[0], p5.y_->value_[0], p5.z_->value_[0]);
  }

  if (!p1.is_equal(p5))
    return false;

  p4.clear();
  p2.x_->value_[0] = 2;
  p2.y_->value_[0] = 23;
  p2.z_->value_[0] = 1;
  p3.x_->value_[0] = 7;
  p3.y_->value_[0] = 145;
  p3.z_->value_[0] = 1;
  if (!projective_add(c1, p2, p3, p4))
    return false;
  // (2472, 715)
  if (FLAGS_print_all) {
    printf("  (%ld, %ld, %ld)", p2.x_->value_[0], p2.y_->value_[0], p2.z_->value_[0]);
    printf(" + ");
    printf("(%ld, %ld, %ld)", p3.x_->value_[0], p3.y_->value_[0], p3.z_->value_[0]);
    printf("= (%ld, %ld, %ld)\n", p4.x_->value_[0], p4.y_->value_[0], p4.z_->value_[0]);
  }
  if (!projective_to_affine(c1, p4))
    return false;
  if (p4.x_->value_[0] != 2472 || p4.y_->value_[0] != 715 || p4.z_->value_[0] != 1)
    return false;
  p5.clear();
  if (!projective_double(c1, p1, p5))
    return false;
  if (!projective_to_affine(c1, p5))
    return false;
  if (p5.x_->value_[0] != 1771 || p5.y_->value_[0] != 705 || p5.z_->value_[0] != 1)
    return false;
  p5.clear();
  if (!projective_point_mult(c1, big_two, p1, p5))
    return false;
  if (!projective_to_affine(c1, p5))
    return false;
  if (p5.x_->value_[0] != 1771 || p5.y_->value_[0] != 705 || p5.z_->value_[0] != 1)
    return false;

  return true;
}

bool test_ecc_curve_point() {
  curve_point p1(2);
  curve_point p2(2);
  curve_point p3(2);
  curve_point p4(2);

  p1.make_zero();
  if (!p1.is_zero())
    return false;

  p1.x_->value_[0] = 2;
  p1.y_->value_[0] = 3;
  p1.z_->value_[0] = 6;
  p1.x_->normalize();
  p1.y_->normalize();
  p1.z_->normalize();

  if (!p2.copy_from(p1))
    return false;
  if (!p1.is_equal(p2))
    return false;
  if (!p2.copy_to(p3))
    return false;
  if (!p1.is_equal(p3))
    return false;
  p3.print();
  return true;
}

bool test_ecc_curve() {
  ecc_curve c1(1);
  ecc_curve c2(2);
  c1.curve_p_->value_[0] = 2773;
  c1.curve_a_->value_[0] = 4;
  c1.curve_b_->value_[0] = 4;
  if (!c2.copy_from(c1))
    return false;
  c2.print_curve();
  c2.clear();
  if (!c2.curve_p_->is_zero() || !c2.curve_a_->is_zero() || !c2.curve_b_->is_zero())
    return false;

  return true;
}

bool test_ecc_class() {

printf("ecc class :\n");
  if (!init_ecc_curves())
    return false;
  p256_key.print();

  ecc key0;
  key0.copy_key_parameters_from(p256_key);
  key0.print();

  ecc key;
  if (!key.generate_ecc_from_standard_template("P-256", "test_key-20",
              "anything", seconds_in_common_year))
    return false;
  key.print();
  if (FLAGS_print_all) {
    printf("Key 1 generate done\n");
  }

  string serialized_str;
  if (!key.get_serialized_key_message(&serialized_str))
    return false;

  ecc key1;
  if (!key1.extract_key_message_from_serialized(serialized_str))
    return false;
  printf("\n");
  key1.print();
  printf("\nPrinting key_message\n");
  print_key_message(*key1.ecc_key_);
  if (FLAGS_print_all) {
    printf("Key 2 extracted message\n");
  }

  if (!key1.retrieve_parameters_from_key_message())
    return false;
  key1.print();
  if (FLAGS_print_all) {
    printf("Key 2 retrieved params\n");
  }

  // if (!set_parameters_in_key_message()) return false;

  return true;
}

bool test_ecc_encrypt_decrypt() {

  byte plain_in[64];
  byte cipher_out[64];
  byte recovered[64];

  memset(plain_in, 0, 64);
  memset(cipher_out, 0, 64);
  memset(recovered, 0, 64);

  if (FLAGS_print_all) {
    printf("encrypt/decrypt test\n");
  }

  if (!init_ecc_curves())
    return false;

  ecc key;
  if (!key.generate_ecc_from_standard_template("P-256", "test_key-20",
              "anything", seconds_in_common_year))
    return false;

  key.print();

  if (key.base_point_ == nullptr) {
    printf("No base point\n");
    return false;
  }
  if (key.public_point_ == nullptr) {
    printf("No public point\n");
    return false;
  }

  if (key.c_ == nullptr) {
    printf("empty curve\n");
    return false;
  }
  if (!ecc_is_on_curve(*key.c_, *key.base_point_)) {
    printf("base point is not on curve\n");
    return false;
  } 
  if (!ecc_is_on_curve(*key.c_, *key.public_point_)) {
    printf("base point is not on curve\n");
    return false;
  } 
    
  printf("base and public are on curve\n\n");

  int size_in = 6;
  int size_out = 64;
  memcpy(plain_in, (byte*)"hello", size_in);

  big_num nonce(10, 0x48283746882294);
  nonce.normalize();
  printf("plain     : "); print_bytes(size_in, plain_in);
  printf("nonce     : "); nonce.print(); printf("\n");

  curve_point pt1(10);
  curve_point pt2(10);

  if (!key.encrypt(size_in, plain_in, nonce, pt1, pt2)) {
    printf("ecc encrypt returns false\n");
    return false;
  }
  if (!key.decrypt(pt1, pt2, &size_out, recovered)) {
    printf("ecc decrypt returns false\n");
    return false;
  }
  printf("cipher    : ("); pt1.print(); printf(" , "); pt2.print(); printf(")\n");
  printf("recovered : "); print_bytes(size_out, recovered); printf("\n");
  if (memcmp(plain_in, recovered, size_in) != 0)
      return false;

  return true;
}

TEST (ecc, test_projective) {
  EXPECT_TRUE(test_ecc_projective());
}
TEST (ecc, test_affine) {
  EXPECT_TRUE(test_ecc_affine_1());
  EXPECT_TRUE(test_ecc_affine_2());
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
