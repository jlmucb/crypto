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
DEFINE_bool(debug, false, "debug flag");
DEFINE_string(bin_freq_file_name, "Dice_freq.bin", "binomial frequency graph file");
DEFINE_string(binomial_terms_file_name, "binomial_terms.bin", "binomial frequency graph file");
DEFINE_string(entropy_sample_file_name, "entropy_sample_file.bin", "entropy sample file graph file");
DEFINE_string(graph_file_1, "test_graph_1.bin", "graph file 1");
DEFINE_string(graph_file_2, "test_graph_2.bin", "graph file 2");

bool test_targeted_sampling() {
  // These are particular to entropy_series:
  //    double calculate_uint32_mean(int num_samples, uint32_t* data);
  //    double calculate_uint32_variance(int num_samples, uint32_t* data, double mean);
  //    double calculate_int16_mean(int num_samples, int16_t* data);
  //    double calculate_int16_variance(int num_samples, int16_t* data, double mean);
  //    bool calculate_second_differences(int num_samples, uint32_t* old_data, int16_t* new_data);
  return true;
}

bool test_sampling() {
  int num_samples = 1000;
  int interval = 100;
  int divisor = 2;
  int num_bits = 6;
  uint32_t data_uint32[num_samples];
  byte data_byte[num_samples];

  zero_uint32_array(num_samples, data_uint32);
  zero_byte_array(num_samples, data_byte);
  if (!collect_difference_samples(num_samples, data_uint32, interval, num_bits, divisor)) {
    return false;
  }
  if (!uint32_to_bytes(num_samples, data_uint32, data_byte)) {
    printf("Can't convert uint32 to bytes\n");
    return false;
  }
  double ent = byte_shannon_entropy(64, num_samples, data_byte);
  if (FLAGS_print_all) {
    printf("Byte entropy: %8.4lf\n", ent);
  }
  if (ent < 5.0)
    return false;

  if (!write_data(FLAGS_entropy_sample_file_name, num_samples, data_uint32)) {
    printf("Can't write file\n");
    return false;
  }
  int new_samples = 0;
  uint32_t* new_data = nullptr;
  if(!read_data(FLAGS_entropy_sample_file_name, &new_samples, &new_data)) {
    printf("Can't read data\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("Written: %d, read: %d\n", num_samples, new_samples);
  }
  if (num_samples != new_samples)
    return false;
  if (memcmp((void*)data_uint32, (void*)new_data, new_samples * sizeof(uint32_t)) != 0)
    return false;
  delete []new_data;
  new_data = nullptr;
  return true;
}

bool test_graph() {
  int nbins = 16;
  uint32_t bins[nbins];

  for (int i = 0; i < nbins; i++)
    bins[i] = 10 * i;
  if(!write_graph_data(FLAGS_graph_file_1, nbins, bins)) {
    return false;
  }

  int num_points = 32;
  double x[num_points];
  double y[num_points];

  for (int i = 0; i < num_points; i++) {
    x[i] = (double) i;
    y[i] = (double) (i * i);
  }
  if (!write_general_graph_data(FLAGS_graph_file_2, num_points, x, y)) {
    return false;
  }

  return true;
}

bool test_conversion() {
  int num_bytes = 256;
  int num_bits = NBITSINBYTE * num_bytes;
  byte bytes_in[num_bytes];
  byte bits[num_bits];
  byte bytes_out[num_bytes];

  zero_byte_array(num_bytes, bytes_in);
  zero_byte_array(num_bytes, bytes_out);
  zero_byte_array(num_bits, bits);

  for (int i = 0; i < num_bytes; i++)
    bytes_in[i] = (i & 0xff);

  if (!byte_to_bits(num_bytes, bytes_in, NBITSINBYTE, num_bits, bits)) {
    return false;
  }
  if (!bits_to_byte(num_bits, bits, NBITSINBYTE, num_bytes, bytes_out)) {
    return false;
  }

  if (FLAGS_debug) {
    printf("bytes in:\n");
    print_bytes(num_bytes, bytes_in);
    printf("\nbits:\n");
    print_bits(num_bits, bits);
    printf("\nbytes out:\n");
    print_bytes(num_bytes, bytes_out);
    printf("\n");
  }
  if (memcmp(bytes_in, bytes_out, num_bytes) != 0)
    return false;

  return true;
}

bool test_bins() {
  int num_samples = 100;
  uint32_t data[num_samples];
  zero_uint32_array(num_samples, data);
  int nbins = 64;
  uint32_t bins[nbins];

  for (int i = 0; i < num_samples; i++) {
    data[i] = i % 37;
  }

  if (!bin_raw_data(num_samples, data, nbins, bins)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("bins:\n");
    print_uint32_array(nbins, bins);
  }

  int total = bin_population(nbins, bins);
  double x[nbins];
  double p[nbins];
  for (int i = 0; i < nbins; i++) {
    x[i] = (double) bins[i];
    p[i] = ((double) bins[i]) / ((double)total);
  }
  double mean = expected_value(nbins, p, x);
  double var = variance(nbins, mean, p, x);
  double shannon_ent = shannon_entropy(nbins, p);
  if (FLAGS_print_all) {
    printf("mean: %8.4lf, variance: %8.4lf, entropy: %8.4lf\n", mean, var, shannon_ent);
  }
  return true;
}

bool test_binomial(double alpha) {

  printf("\nBinomial test\n");
  double residual = 0.0;

  int num_rolls = 36;
  byte dice_roll[num_rolls];

  int r;
  for(int i = 0; i < num_rolls; i++) {
    r = non_binary_random(6);
    if (r < 0)
      return false;
    dice_roll[i] = (byte)r;
  }

  byte roll_count[6];
  if (!bin_raw_byte_data(num_rolls, dice_roll, 6, roll_count)) {
    printf("Can't bin dice data\n");
    return false;
  }

  double p = 1.0 / 6.0;
  double freq[6];
  for (int i = 0; i < 6; i++) {
    freq[i] = ((double)roll_count[i]) / ((double) num_rolls);
  }

  if (FLAGS_print_all) {
    printf("\nDice rolls:\n");
    print_bytes(num_rolls, dice_roll);
    printf("\ncounts, expected frequency: %lf, expected count: %lf\n", p, p * ((double)num_rolls));
    for (int i = 0; i < 6; i++) {
      printf("%d: %d, %5.3lf; ", i, roll_count[i], freq[i]);
    }
    printf("\n");
  }

  // Graph frequencies and binomial terms
  double x[num_rolls + 1];
  double y[num_rolls + 1];

  zero_double_array(num_rolls, x);
  zero_double_array(num_rolls, y);
  for (int i = 0; i < 6; i++) {
    x[i] = (double)(i + 1);
    y[i] = freq[i];
  }
  if (!write_general_graph_data(FLAGS_bin_freq_file_name, 6, x, y)) {
    printf("Can't write dice frequency file\n");
    return false;
  }

  zero_double_array(num_rolls + 1, x);
  zero_double_array(num_rolls + 1, y);
  for (int i = 0; i < (num_rolls + 1); i++) {
    x[i] = (double)i;
    y[i] = binomial_term(num_rolls, i, p);
  }
  if (!write_general_graph_data(FLAGS_binomial_terms_file_name, num_rolls + 1, x, y)) {
    printf("Can't write dice binomial file\n");
    return false;
  }

  byte success = 1;
  if (binomial_test(num_rolls, dice_roll, success, p, alpha, &residual)) {
    printf("Binomial test for dice succeeds, success: %d, residual: %lf\n", success, residual);
  } else {
    printf("Binomial test for dice fails, success: %d, residual: %lf\n", success, residual);
  }
  printf("\n");
  return true;
}

bool test_statistical_tests() {
  int num_samples = 1000;
  int interval = 100;
  int divisor = 2;
  int num_bits = 6;
  uint32_t data_uint32[num_samples];
  byte data_byte[num_samples];

  zero_uint32_array(num_samples, data_uint32);
  zero_byte_array(num_samples, data_byte);
  if (!collect_difference_samples(num_samples, data_uint32, interval, num_bits, divisor)) {
    return false;
  }
  if (!uint32_to_bytes(num_samples, data_uint32, data_byte)) {
    printf("Can't convert uint32 to bytes\n");
    return false;
  }
  double ent = byte_shannon_entropy(63, num_samples, data_byte);
  if (FLAGS_print_all) {
    printf("Byte entropy: %8.4lf\n", ent);
  }

  double t1 = factorial(5);
  double t2 = choose(10, 5);
  if (t1 != 120.0)
    return false;
  if (t2 != 252.0)
    return false;

  double residual = 0.0;
  double alpha = .01;
  int tmp_num_samples = 256;
  byte most_common = most_common_byte(tmp_num_samples, data_byte);
  double p_test =  1.0 / ((double)(1 << num_bits));
  alpha = .01;

  if (FLAGS_print_all) {
    printf("samples:\n");
    print_bytes(tmp_num_samples, data_byte);
    printf("\n");
  }

  if (binomial_test(tmp_num_samples, data_byte, most_common, p_test, alpha, &residual)) {
    printf("Binomial test succeeds, mcv: %x, residual: %lf\n", most_common, residual);
  } else {
    printf("Binomial test fails, mcv: %x, residual: %lf\n", most_common, residual);
  }

  double mcv_ent = most_common_value_entropy(64, num_samples, data_byte);
  printf("Most common ent: %8.4lf\n", mcv_ent);

  int num_runs = 0;
  double mu = 0.0;
  double sig = 0.0;
  if (!runs_test(num_samples, data_byte, &num_runs, &mu, &sig)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("Runs test, mu: %8.4lf, sig: %8.4lf\n", mu, sig);
  }
  double markov_ent = byte_markov_entropy(num_samples, data_byte);
  if (FLAGS_print_all) {
    printf("Markov entropy: %8.4lf\n", markov_ent);
  }
  int result = 0;
  int lag = 5;
  if (!periodicity_test(num_samples, data_byte, lag, &result)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("Periodicity result: %d\n", result);
  }

  int size = 0;
  if (!compression_test(num_samples, data_byte, &size)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("Compression test, Original size: %d, compressed size: %d\n", num_samples, size);
  }
  
  // double byte_markov_sequence_probability(int seq_len, byte* seq,
  //        double p_0, double p_1, double p_00, double p_01, double p_10, double p_11);
  // bool real_dft(int n, double* data, double* transform);
  // bool berlekamp_massy(int n, byte* s, int* L);

  double excursion = excursion_test(num_samples, data_byte);
  if (FLAGS_print_all) {
    printf("Excursion test: %8.4lf\n", excursion);
  }

  int n = 256; 
  byte values[n];
  int nbins = 16;
  double p[nbins];

  double epsilon = .003;
  for (int i = 0; i < n; i++) {
      values[i] = (byte) (i % 16);
  }
  for (int i = 0; i < nbins; i++) {
    if ((i%2) == 0)
      p[i] = 1.0 / ((double)nbins) + epsilon;
    else
      p[i] = 1.0 / ((double)nbins) - epsilon;
  }
  double chi_value = 0.0;

  int v = 10;
  double lower = chi_critical_lower(v, 0.10);
  double upper = chi_critical_upper(v, 0.95);
  if (fabs(upper - 18.307) > .001)
    return false;
  if (fabs(lower - 4.865) > .001)
    return false;

  if (!chi_squared_test(n, values, nbins, p, &chi_value)) {
    return false;
  }
  int nu_sample = nbins - 1;
  double confidence = 0.10;
  upper = chi_critical_upper(nu_sample, 1.0 - confidence);
  if (chi_value > upper)  // reject
    printf("REJECT at %4.2lf, Chi value: %8.4lf, upper confidence: %8.5lf\n", confidence, chi_value, upper);
  else
    printf("ACCEPT at %4.2lf, Chi value: %8.4lf, upper confidence: %8.5lf\n", confidence, chi_value, upper);
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

  if (FLAGS_debug) {
    printf("p_xy:\n");
    for (int i = 0; i < n; i++) {
      for (int j = 0; j < n; j++) {
        printf("%5.3lf ", p_xy[index(n,n,i,j)]);
      }
      printf("\n");
    }
  }

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

  double q[n];
  if (!calculate_marginal_probability(n, n, 0, p_xy, q)) {
    return false;
  }
  printf("Marginal probabilities:\n");
  print_double_array(n, q);

  return true;
}

TEST(sampling, test_sampling) {
  EXPECT_TRUE(test_sampling());
  EXPECT_TRUE(test_targeted_sampling());
}
TEST(graph, test_graph) {
  EXPECT_TRUE(test_graph());
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
TEST (binomial, test_binomial) {
  EXPECT_TRUE(test_binomial(0.01));
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
