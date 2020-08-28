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

TEST (algs, test_alg_names) {
  EXPECT_TRUE(test_alg_names());
}
TEST (timeutilities, time_convert_test) {
  EXPECT_TRUE(time_convert_test());
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
