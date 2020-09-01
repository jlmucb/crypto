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
// File: big_num_test.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include "crypto_support.h"
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "big_num.h"
#include "intel_digit_arith.h"

DEFINE_bool(print_all, false, "Print intermediate test computations");

bool basic_digit_test1() {
  return true;
}

bool decimal_convert_test1() {
  uint64_t n[2];
  n[0]= 301;
  n[1]= 1;
  string s;
  uint64_t m[3];

  digit_array_zero_num(3, m);
  if (!digit_convert_to_decimal(1, n, &s))
    return false;
  if (!digit_convert_from_decimal(s, 2, m))
    return false;
  if (digit_array_compare(1, n, 2, m) != 0)
    return false;
  if (FLAGS_print_all)
    printf("n: %lld, %s\n", n[0], s.c_str());

  digit_array_zero_num(3, m);
  if (!digit_convert_to_decimal(2, n, &s))
    return false;
  if (!digit_convert_from_decimal(s, 3, m))
    return false;
  if (digit_array_compare(2, n, 3, m) != 0)
    return false;

  if (FLAGS_print_all) 
    printf("n: %lld %lld, %s\n", n[1], n[0], s.c_str());
  return true;
}

TEST(basic_tests, basic_digit_test1) {
  EXPECT_TRUE(basic_digit_test1());
}
TEST(decimal, convert) {
  EXPECT_TRUE(decimal_convert_test1());
}

int main(int an, char** av) {

  uint64_t cycles_per_second = calibrate_rdtsc();
  printf("This computer has %llu cycles per second\n", cycles_per_second);

  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!init_crypto()) {
    printf("Can't init_crypto\n");
    return 1;
  }

  int result = RUN_ALL_TESTS();
  printf("%d Tests complete\n", result);

  close_crypto();
  return 1;
}

