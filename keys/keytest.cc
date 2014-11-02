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
// Project: New Cloudproxy Crypto
// File: keytest.cc

#include "cryptotypes.h"
#include "gtest/gtest.h"

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string>
#include "keys.pb.h"
#include "keys.h"
#include "util.h"
#include "string.h"
#include "conversions.h"
#include <cmath>

class KeyTest : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void KeyTest::SetUp() {
}

void KeyTest::TearDown() {
}

bool simpletest1() {
  SymmetricKey  the_key;
  SymmetricKey  new_key;

  if(!the_key.GenerateAesKey("JohnsKey", "channel-encryption", 
            "John Manferdelli", 128, COMMON_YEAR_SECONDS)) {
    printf("GenerateAesKey failed\n");
    return false;
  }
  printf("Original key:\n");
  the_key.PrintKey();
  printf("\n");

  string  filename("jlmTestSave1");
  if(!((CryptoKey*)&the_key)->SaveKey(filename)) {
    printf("SaveKey failed\n");
    return false;
  }

  if(!((CryptoKey*)&new_key)->ReadKey(filename)) {
    printf("ReadKey failed\n");
    return false;
  }
  printf("Recovered key:\n");
  new_key.PrintKey();
  printf("\n");
  return true;
}

bool RunTestSuite() {
  KeyStore      key_store;
  SymmetricKey  the_key;

  if(!the_key.GenerateAesKey("JohnsStoreKey1", "channel-encryption", 
            "John Manferdelli", 128, COMMON_YEAR_SECONDS)) {
    printf("GenerateAesKey failed\n");
    return false;
  }

  if(!key_store.ReadStore("TestKeyStore")) {
    printf("Cant read key store\n");
    return false;
  }
  if(!key_store.AddKey((CryptoKey*)&the_key)) {
    printf("Cant add to key store\n");
    return false;
  }

  CryptoKey*    p_msg= NULL;
  string*       p_string= NULL;
  if(!key_store.FindKey("JohnsStoreKey1", &p_string, &p_msg)) {
    printf("Cant find key in store\n");
    return false;
  }
  ((SymmetricKey*)p_msg)->PrintKey();
  return true;
}

TEST(FirstKeyCase, FirstKeyTest) {
  EXPECT_TRUE(simpletest1());
}

TEST_F(KeyTest, RunTestSuite) {
  EXPECT_TRUE(RunTestSuite());
}

DEFINE_string(log_file, "keytest.log", "keytest logging file name");

int main(int an, char** av) {

  ::testing::InitGoogleTest(&an, av);
  if(!InitUtilities(FLAGS_log_file.c_str())) {
    printf("InitUtilities() failed\n");
    return 1;
  }
  int result= RUN_ALL_TESTS();
  CloseUtilities();
  return result;
}


