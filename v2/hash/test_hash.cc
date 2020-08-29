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
// File: test_hash.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
//#include "hash.h"

DEFINE_bool(print_all, false, "Print intermediate test computations");

bool test_sha1() {
  return true;
}

bool test_sha2_a() {
  return true;
}

bool test_sha2_b() {
  return true;
}

bool test_sha2_c() {
  return true;
}

bool test_sha3() {
  return true;
}

bool test_ghash() {
  return true;
}

bool test_hmac_sha256() {
  return true;
}

bool test_pkcs1() {
  return true;
}

bool test_pkdf2() {
  return true;
}

bool test_cmac() {
  return true;
}

TEST (pkcs1, test_pkcs1) {
  EXPECT_TRUE(test_pkcs1());
}
TEST (sha1, test_sha1) {
  EXPECT_TRUE(test_sha1());
}
TEST (sha2, sha2) {
  EXPECT_TRUE(test_sha2_a());
  EXPECT_TRUE(test_sha2_b());
  EXPECT_TRUE(test_sha2_c());
}
TEST (sha3, test_sha3) {
  EXPECT_TRUE(test_sha1());
}
TEST (ghash, test_ghash) {
  EXPECT_TRUE(test_ghash());
}
TEST (hmac, test_hmac_sha256) {
  EXPECT_TRUE(test_hmac_sha256());
}
TEST (pkdf, test_pkdf2) {
  EXPECT_TRUE(test_pkdf2());
}
TEST (cmac, test_cmac) {
  EXPECT_TRUE(test_cmac());
}


int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  int result = RUN_ALL_TESTS();
  printf("%d tests\n", result);
  printf("Tests complete\n");
  return 0;
}
