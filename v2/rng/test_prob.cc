// Copyright 2014-2020 John Manferdelli, All Rights Reserved.
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
// File: test_prob.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include "crypto_support.h"
#include "support.pb.h"
#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include "probability_support.h"

DEFINE_bool(print_all, false, "print flag");

bool test_bins() {
  return true;
}

bool test_probability_calculations() {

  double x[16] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16,
  };
  double a = 1/16.0;
  double p[16] = {
    a, a, a, a, a, a, a, a,
    a, a, a, a, a, a, a, a,
  };

  int n = 16;
  if (FLAGS_print_all) {
    printf("x:\n");
    print_double_array(n, x);
    printf("p:\n");
    print_double_array(n, p);
  }

  double mean = expected_value(n, p, x);
  double var = variance(n, mean, p, x);
  if (FLAGS_print_all) {
    printf("mean: %8.4lf, variance: %8.4lf\n", mean, var);
  }
  double sh_ent= shannon_entropy(n, p);
  double re_ent= renyi_entropy(n, p);
  double min_ent = min_entropy(n, p);
  printf("shannon: %8.4lf, renyi: %8.4lf, min: %8.4lf\n", sh_ent, re_ent, min_ent);
  // double covariance(int n, int m, double mean_x, double* x, double mean_y, double* y, double* p_xy) {
  // double correlate(int n, int m, double mean_x, double sigma_x, double* x, double mean_y, double sigma_y, double* y, double* p_xy) {

  return true;
}

TEST (test_bins, test_bins) {
  EXPECT_TRUE(test_bins());
}

TEST (probability, test_probability_calculations) {
  EXPECT_TRUE(test_probability_calculations());
}

// entropy series generates time series differences
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
  return result;
}
