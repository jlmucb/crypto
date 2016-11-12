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
#include "gf2_common.h"

#include <memory>
#include <cmath>

DEFINE_bool(printall, false, "printall flag");

class GF2Common : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void GF2Common::SetUp() {}

void GF2Common::TearDown() {}

/*
int real_size(int size_in, byte* in);
bool gf2_mult(int size_in1, byte* in1, int size_in2, byte* in2,
              int size_min_poly, byte* min_poly, int* size_out, byte* out);
bool gf2_add(int size_in1, byte* in1, int size_in2, byte* in2,
             int size_min_poly, byte* min_poly, int* size_out, byte* out);
bool gf2_reduce(int size_min_poly, byte* min_poly,
                int* size_in_out, byte* in_out);
void print_poly(int size_in, byte* in);
bool to_internal_representation(uint16_t in, int* size_out, byte* out);
bool from_internal_representation( int size_in, byte* in, uint16_t* out);
 */


bool InternalRepTest() {
  uint16_t tpoly = 0x77;
  uint16_t cpoly;
  int size_a = 16;
  byte a[16];
  EXPECT_TRUE(to_internal_representation(tpoly, &size_a, a));
  EXPECT_TRUE(from_internal_representation(size_a, a, &cpoly));
  printf("Cpoly: %02x\n", cpoly);
  EXPECT_TRUE(tpoly == cpoly);
  return true;
}

bool PrintPolyTest() {
  uint16_t tpoly = 0x77;
  int size_a = 16;
  byte a[16];
  EXPECT_TRUE(to_internal_representation(tpoly, &size_a, a));
  print_poly(size_a, a);
  printf("\n");
  return true;
}

TEST(InternalRep, InternalRepTest) {
  EXPECT_TRUE(InternalRepTest());
}
TEST(PrintPoly, PrintPolyTest) {
  EXPECT_TRUE(PrintPolyTest());
}


DEFINE_string(log_file, "gf2_common_test.log", "gf2_common_test file name");

int main(int an, char** av) {
  ::testing::InitGoogleTest(&an, av);
#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif
  int result = RUN_ALL_TESTS();
  return result;
}
