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
// File: symmetric.cc

#include <stdio.h>
#include <string.h>

#include <string>

#include "util.h"
#include "cryptotypes.h"
#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include "lattice_support.h"

#include <memory>
#include <cmath>



class LatticeTest : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void LatticeTest::SetUp() {}

void LatticeTest::TearDown() {}


bool RejectionTest() {
  bool flag;
  double mean = 0;
  double var = 1.0;
  double x = 0;

  for (int i = 0; i < 25; i++) {
    flag = RejectNormal(x, mean, var);
    if (flag) {
      printf("Accept %10.7f\n", x);
    } else {
      printf("Reject %10.7f\n", x);
    }
    x += .08;
  }
  return true;
}

TEST(RejectionTest, RejectionTest) {
  EXPECT_TRUE(RejectionTest());
}

DEFINE_bool(printall, false, "printall flag");
DEFINE_string(log_file, "latticetest.log", "latticetest file name");

int main(int an, char** av) {
  ::testing::InitGoogleTest(&an, av);
#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif
#if 0
  if (!InitUtilities(FLAGS_log_file.c_str())) {
    printf("InitUtilities() failed\n");
    return 1;
  }
  int result = RUN_ALL_TESTS();
  CloseUtilities();
#endif
  int result = RUN_ALL_TESTS();
  return result;
}
