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
// 
// File: schooftest.cc

#include "cryptotypes.h"
#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "util.h"
#include "indeterminate.h"
#include "ecc_symbolic.h"

uint64_t  cycles_per_second= 10;


class SchoofTest : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void SchoofTest::SetUp() {
}

void SchoofTest::TearDown() {
}

Polynomial* one_poly= NULL;
Polynomial* x_poly= NULL;
Polynomial* x_plus_one_poly= NULL;

bool InitPolys(BigNum* c) {
  // p(x)= 1
  one_poly= new Polynomial(1, 1, *c);
  one_poly->c_[0]->value_[0]= 1ULL;
  // p(x)= x
  x_poly= new Polynomial(1, 2, *c);
  x_poly->c_[1]->value_[0]= 1ULL;
  // p(x)= x+1
  x_plus_one_poly= new Polynomial(1, 2, *c);
  x_plus_one_poly->c_[0]->value_[0]= 1ULL;
  x_plus_one_poly->c_[1]->value_[0]= 1ULL;
  return true;
}

bool SimpleSymbolicTest() {
  return true;
}

bool SimpleSchoofTest() {
  return true;
}
 
TEST(SimpleTest, SimpleTest) {
  EXPECT_TRUE(SimpleSymbolicTest());
  EXPECT_TRUE(SimpleSchoofTest());
}

DEFINE_string(log_file, "schooftest.log", "schooftest file name");

int main(int an, char** av) {

  BigNum  c(1,31ULL);

  if(!InitPolys(&c)) {
    printf("Can't init polys\n");
    return 1;
  }
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


