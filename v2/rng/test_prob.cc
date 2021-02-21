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

bool test_targeted_sampling() {
  // double calculate_uint32_mean(int num_samples, uint32_t* data);
  // double calculate_uint32_variance(int num_samples, uint32_t* data, double mean);
  // double calculate_int32_mean(int num_samples, int16_t* data);
  // double calculate_int32_variance(int num_samples, int16_t* data, double mean);
  // bool calculate_second_differences(int num_samples, uint32_t* old_data, int16_t* new_data);
  return true;
}

bool test_sampling() {
  // bool collect_difference_samples(int num_samples, uint32_t* data,
  //             uint32_t interval, int num_bits, int divisor);
  return true;
}

bool test_graph() {
  // bool write_graph_data(string file_name, int nbins, uint32_t* bins);
  // bool write_general_graph_data(string file_name, int n, double* x, double* y);
  return true;
}

bool test_io() {
  // bool write_data(string file_name, int num_samples, uint32_t* data);
  // bool read_data(string file_name, int* num_samples, uint32_t** data);
  return true;
}

bool test_conversion() {
  // bool bits_to_byte(int n_bit_bytes, byte* all_bits_in_byte,
  //                   int n_one_bit_per_byte, byte* one_bit_per_byte);
  // bool byte_to_bits(int n_one_bit_per_byte, byte* one_bit_per_byte,
  //                   int n_bit_bytes, byte* all_bits_in_byte);
  return true;
}

bool test_bins() {
  // bool bin_conditional_data(int num_samples, uint32_t* data, int nbins, uint32_t* bins, uint32_t base_bin);
  // bool bin_raw_data(int num_samples, uint32_t* data, int nbins, uint32_t* bins);
  // bool bin_int32_data(int num_samples, int16_t* data, int nbins, uint32_t* bins);
  return true;
}

bool test_statistical_tests() {

  // double most_common_value_entropy(int largest_possible_sample,
  //           int num_samples, byte* samples);
  // double byte_markov_sequence_probability(int seq_len, byte* seq,
  //   double p_0, double p_1, double p_00, double p_01, double p_10, double p_11);
  // double byte_markov_entropy(int num_samples, byte* samples);
  // double byte_shannon_entropy(int largest_possible_sample,
  //         int num_samples, byte* samples);
  // bool real_dft(int n, double* data, double* transform);
  // bool runs_test(int n, byte* s, int* number_of_runs, double* mu, double* sigma);
  // bool berlekamp_massy(int n, byte* s, int* L);
  // double excursion_test(int n, byte* s);
  // bool chi_squared_test(int n, byte* x, int num_values, double* p, double* chi_value);
  // bool periodicity_test(int n, byte* s, int lag, int* result);
  // bool compression_test(int n, byte* s, int* compressed);
  return true;
}

bool test_probability_calculations() {

  double x[16] = {
    0, 1,  2,  3,  4,  5,  6,  7,
    8, 9, 10, 11, 12, 13, 14, 15,
  };
  double a = 1/16.0;
  double p[16] = {
    a, a, a, a, a, a, a, a,
    a, a, a, a, a, a, a, a,
  };

  int n = 16;

  double p_xy[n * n];
  for (int i = 0; i < (n * n); i++)
    p_xy[i]= a * a;

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
  if (fabs(mean - 7.5) > .001)
    return false;
  if (fabs(var - 21.25) > .001)
    return false;

  double sh_ent= shannon_entropy(n, p);
  double re_ent= renyi_entropy(n, p);
  double min_ent = min_entropy(n, p);
  printf("shannon: %8.4lf, renyi: %8.4lf, min: %8.4lf\n", sh_ent, re_ent, min_ent);
  printf("\n");
  if (fabs(sh_ent - 4.000) > .001)
    return false;
  if (fabs(re_ent - 4.000) > .001)
    return false;
  if (fabs(min_ent - 4.000) > .001)
    return false;

  if (FLAGS_print_all) {
    printf("p_xy:\n");
    for (int i = 0; i < n; i++) {
      for (int j = 0; j < n; j++) {
        printf("%5.3lf ", p_xy[index(n,n,i,j)]);
      }
      printf("\n");
    }
  }
  printf("\n");

  double cov = covariance(n, n, mean, x, mean, x, p_xy);
  double rho = correlate(n, n, mean, sqrt(var), x, mean, sqrt(var), x, p_xy);
  printf("covariance: %8.4lf, correlation: %8.4lf\n", cov, rho);
  printf("\n");

  double b = 2.0 * p[0];
  for (int i = 0; i < n; i++) {
    if (i >= 8) {
      if ((i%2) == 0)
        p[i] = 0.0;
      else
        p[i] = b;
    }
  }
  if (FLAGS_print_all) {
    printf("x:\n");
    print_double_array(n, x);
    printf("p:\n");
    print_double_array(n, p);
  }
  mean = expected_value(n, p, x);
  var = variance(n, mean, p, x);
  if (FLAGS_print_all) {
    printf("mean: %8.4lf, variance: %8.4lf\n", mean, var);
  }
  sh_ent= shannon_entropy(n, p);
  re_ent= renyi_entropy(n, p);
  min_ent = min_entropy(n, p);
  printf("shannon: %8.4lf, renyi: %8.4lf, min: %8.4lf\n", sh_ent, re_ent, min_ent);
  printf("\n");

  // bool calculate_marginal_probability(int n, int m, int var_num, double* p_xy, double* p)

  return true;
}

TEST(sampling, test_sampling) {
  EXPECT_TRUE(test_sampling());
  EXPECT_TRUE(test_targeted_sampling());
}
TEST(graph, test_graph) {
  EXPECT_TRUE(test_graph());
}
TEST(io, test_io) {
  EXPECT_TRUE(test_io());
}
TEST(conversion, test_conversion) {
  EXPECT_TRUE(test_conversion());
}
TEST (bins, test_bins) {
  EXPECT_TRUE(test_bins());
}
TEST (probability, test_probability_calculations) {
  EXPECT_TRUE(test_probability_calculations());
}
TEST(statistics, test_statistical_tests) {
  EXPECT_TRUE(test_statistical_tests());
}

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
