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
// File: test_crypto_support.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"

bool test_alg_names() {
  printf("schemes:\n");
  print_schemes();
  printf("\n");
  printf("algorithms:\n");
  print_algorithms();
  printf("\n");
  printf("operations:\n");
  print_operations();
  printf("\n");
  return true;
}

bool time_convert_test() {
  time_point t;
  
  t.time_now();
  t.print_time();
  printf("\n");
  return true;
}

bool random_test() {
  random_source rs;

  if (!rs.start_random_source()) {
    return false;
  }
  byte b[64];
  int m = rs.get_random_bytes(64, b);
  if (m < 0)
    return false;
  print_bytes(m, b);
  return rs.close_random_source();
}

string test_hex_string1("012ab33");
string test_hex_string2("a012ab334466557789");

bool hex_convert_test() {
  string b1(50, 0);
  string b2(50, 0);
  b1.clear();
  b2.clear();

  printf("hex 1: %s\n", test_hex_string1.c_str());
  printf("hex 2: %s\n", test_hex_string2.c_str());
  if (!hex_to_bytes(test_hex_string1, &b1, false))
    return false;
  if (!hex_to_bytes(test_hex_string1, &b1, false))
    return false;
  if (!hex_to_bytes(test_hex_string2, &b2, false))
    return false;
  printf("b1: ");
  print_bytes((int)b1.size(), (byte*)b1.data());
  printf("b2: ");
  print_bytes((int)b2.size(), (byte*)b2.data());
  
  string c1(50, 0);
  string c2(50, 0);
  if (!bytes_to_hex(b1, &c1, false))
    return false;
  if (!bytes_to_hex(b2, &c2, false))
    return false;
  printf("c1: %s\n", c1.c_str());
  printf("c2: %s\n", c2.c_str());

  string d1(50, 0);
  string d2(50, 0);
  if (!hex_to_bytes(c1, &d1, false))
    return false;
  if (!hex_to_bytes(c2, &d2, false))
    return false;
  printf("d1: ");
  print_bytes((int)d1.size(), (byte*)d1.data());
  printf("d2: ");
  print_bytes((int)d2.size(), (byte*)d2.data());

  if (d1.compare(b1) != 0)
    return false;
  if (d2.compare(b2) != 0)
    return false;
  return true;
}

TEST (algs, test_alg_names) {
  EXPECT_TRUE(test_alg_names());
}
TEST (timeutilities, time_convert_test) {
  EXPECT_TRUE(time_convert_test());
}
TEST (convertutilities, hex_convert_test) {
  EXPECT_TRUE(hex_convert_test());
}
TEST (randomutilities, random_test) {
  EXPECT_TRUE(random_test());
}
#if 0
TEST (convertutilities, convert_test) {
  EXPECT_TRUE(time_convert_test());
}
TEST (fileutilities, file_test) {
  EXPECT_TRUE(time_convert_test());
}
TEST (keyutilities, key_test) {
  EXPECT_TRUE(time_convert_test());
}
#endif

int main(int an, char** av) {
  //gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  uint64_t cycles_per_second = calibrateRdtsc();
  printf("This computer runs at %llu cycles per second\n", cycles_per_second);
  if (have_intel_rd_rand())
    printf("rd rand present\n");
  else
    printf("rd rand not present\n");
  if (have_intel_aes_ni())
    printf("aes ni present\n");
  else
    printf("aes ni not present\n");
  int result = RUN_ALL_TESTS();
  printf("%d tests\n", result);
  printf("Tests complete\n");
  return 0;
}
