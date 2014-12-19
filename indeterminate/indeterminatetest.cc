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
// File: indeterminatetest.cc

#include "cryptotypes.h"
#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "util.h"
#include "indeterminate.h"

uint64_t  cycles_per_second= 10;


class IndeterminateTest : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void IndeterminateTest::SetUp() {
}

void IndeterminateTest::TearDown() {
}
 
bool SimplePolyTest() {
  return true;
}
 
TEST(SimplePolyTest, SimplePolyTest) {
  EXPECT_TRUE(SimplePolyTest());
}

DEFINE_string(log_file, "indeterminatetest.log", "indeterminatetest file name");

int main(int an, char** av) {

  ::testing::InitGoogleTest(&an, av);
  if(!InitUtilities(FLAGS_log_file.c_str())) {
    printf("InitUtilities() failed\n");
    return 1;
  }
  cycles_per_second= CalibrateRdtsc();
  printf("Cycles per second on this machine: %lld\n\n", cycles_per_second);
  int result= RUN_ALL_TESTS();
  CloseUtilities();
  return result;
}


