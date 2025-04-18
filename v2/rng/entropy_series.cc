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
// File: entropy_series.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include "crypto_support.h"
#include "support.pb.h"
#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include "probability_support.h"

DEFINE_bool(debug, true, "Debug flag");
DEFINE_bool(do_conditional, false, "Analyze conditional entropy");
DEFINE_bool(print_bins, false, "Print bins");
DEFINE_string(num_samples, "1000", "number of samples");
DEFINE_string(interval, "1000", "interval in us");
DEFINE_string(divisor, "2", "divisor");
DEFINE_string(num_bits, "6", "number of bits");
DEFINE_string(output_file, "tick_difference_output.bin", "output file");
DEFINE_string(graph_file, "graph.bin", "graph output file");
DEFINE_string(second_graph_file, "graph2.bin", "second graph output file");
DEFINE_string(significance_level, "0.05", "significance level for chi tests");

// entropy series generates time series differences
int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  if (!init_crypto()) {
    printf("init_crypto failed\n");
    return 1;
  }

  int interval, num_samples;
  int num_bits = 6;
  int divisor = 2;
  double significance_level = 0.05;

  sscanf(FLAGS_interval.c_str(), "%d", &interval);
  sscanf(FLAGS_num_samples.c_str(), "%d", &num_samples);
  sscanf(FLAGS_divisor.c_str(), "%d", &divisor);
  sscanf(FLAGS_num_bits.c_str(), "%d", &num_bits);
  sscanf(FLAGS_significance_level.c_str(), "%lf", &significance_level);

  uint64_t num_ticks_per_sec = calibrate_rdtsc();


  printf("\ninterval: %d us, samples: %d, ticks/second: %lu, num_bits: %d, bins: %d, divisor: %d\n", 
    interval, num_samples, num_ticks_per_sec, num_bits, 1<<num_bits, divisor);

  uint32_t diffs[num_samples];
  zero_uint32_array(num_samples, diffs);
  if (!collect_difference_samples(num_samples, diffs,
            interval, num_bits, divisor)) {
    printf("Can't collect samples\n");
    return 1;
  }

  if (FLAGS_print_bins) {
    printf("\nCollected differences:\n");
    print_hex_uint32_array(num_samples, diffs);
    printf("\n");
  }

  if (!write_data(FLAGS_output_file, num_samples, diffs)) {
    printf("Can't write data\n");
    return 1;
  }

  double mean = calculate_uint32_mean(num_samples, diffs);
  double var = calculate_uint32_variance(num_samples, diffs, mean);
  double sigma = sqrt(var);
  printf("mean: %8.3lf, variance: %8.3lf, sigma: %8.3lf\n", mean, var, sigma);

  int nbins = 1<<num_bits;
  uint32_t bins[nbins];
  zero_uint32_array(nbins, bins);
  if (!bin_raw_data(num_samples, diffs, nbins, bins)) {
    printf("Can't bin data\n");
    return 1;
  }

  if (true) {
    printf("bin frequencies:\n");
    for (int i = 0; i < nbins; i++) {
      printf("%5.3lf ", ((double)bins[i]) / ((double)num_samples));
      if ((i%8) == 7)
        printf("\n");
    }
    printf("\n");
  }

  printf("\nChi squared test on differences:\n");
  byte_t values[num_samples];
  zero_byte_array(num_samples, values);
  if (uint32_to_bytes(num_samples, diffs, values)) {

    // flat distribution
    double p[num_samples];
    for (int i = 0; i < nbins; i++)
      p[i] = 1.0 / ((double)nbins);

    printf("chi bins, %8.4lf:\n", p[0]);
    print_uint32_array(nbins, bins);
    printf("\n");

    double chi_value = 0.0;
    if (!chi_squared_test(num_samples, values, nbins, p, &chi_value)) {
      return 1;
    }
    int nu_sample = nbins - 1;
    double upper = chi_critical_upper(nu_sample, 1.0 - significance_level);
    if (chi_value > upper)  // reject
      printf("REJECT at %4.2lf, Chi value: %8.4lf, upper: %8.5lf\n",
        significance_level, chi_value, upper);
    else
      printf("ACCEPT at %4.2lf, Chi value: %8.4lf, upper: %8.5lf\n",
        significance_level, chi_value, upper);

    // bitstring estimate
    int num_bit_samples = num_bits * num_samples;
    byte_t the_bits[num_bit_samples];
    if (!byte_to_bits(num_samples, values, num_bits,
                  num_bit_samples, the_bits)) {
      printf("Can't convert to bits\n");
      return 1;
    }
    int num0 = 0;
    int num1 = 0;
    for (int i = 0; i < num_bit_samples; i++) {
      if (the_bits[i] == 0)
        num0++;
      else
        num1++;
    }
    double p_bin[2];
    p_bin[0] = ((double) num0) / ((double) num_bit_samples);
    p_bin[1] = ((double) num1) / ((double) num_bit_samples);

    double bit_string_shannon_entropy = shannon_entropy(2, p_bin);
    double bit_string_renyi_entropy = renyi_entropy(2, p_bin);
    double bit_string_min_entropy = min_entropy(2, p_bin);
    printf("\n%7.5lf, %7.5lf\n", p_bin[0], p_bin[1]);
    printf("Bit sting entropies, shannon: %6.4lf, renyi: %6.4lf, min: %6.4lf\n",
           bit_string_shannon_entropy, bit_string_renyi_entropy, bit_string_min_entropy);
  }

  if (FLAGS_print_bins) {
    printf("\nbins:\n");
    print_uint32_array(nbins, bins);
    printf("\n");
  }

#if 0
  printf("test calcs\n");
  double pp[nbins], xx[nbins];
  for (int i = 0; i < nbins; i++) {
    xx[i] = (double) i;
    pp[i] = ((double)bins[i]) / ((double)num_samples);
  }

  double test_mean = expected_value(nbins, pp, xx);
  double test_var = variance(nbins, test_mean, pp, xx);
  double test_shannon = shannon_entropy(nbins, pp);
  double test_renyi = renyi_entropy(nbins, pp);
  double test_min = min_entropy(nbins, pp);
  printf("test_mean: %8.4lf, test_variance: %8.4lf, test_shannon: %8.4lf, test_renyi: %8.4lf, test_min: %8.4lf\n",
      test_mean, test_var, test_shannon, test_renyi, test_min);

#endif

  double shannon_entropy = 0.0;
  double renyi_entropy = 0.0;
  double min_entropy = 0.0;
  if (!calculate_bin_entropies(num_samples, nbins, bins, &shannon_entropy,
        &renyi_entropy, &min_entropy)) {
    printf("Can't calculate entropies\n");
    return 1;
  }
  printf("shannon entropy: %5.3lf, renyi entropy: %5.3lf, min entropy: %5.3lf\n", 
        shannon_entropy, renyi_entropy, min_entropy);

  double normal_dist_ent = (.5 * (1.0 + log(2.0 * var * pi))) / log(2.0);
  printf("Normal distribution estimate: %8.3lf\n", normal_dist_ent);
#if 0
  //correction
  double s1 = sigma * 1.20;
  double a1 = erf(-mean / s1);
  double a2 = erf((((double)nbins) - mean) / s1);
  double a3= (fabs(a1) + a2) / 2.0;
  printf("a1: %8.5lf, a2: %8.5lf, a3: %8.5lf  %8.5lf\n", a1, a2, a3, a3 * normal_dist_ent);
#endif
  printf("\n");

printf("Writing %d bins\n", nbins);
  if (!write_graph_data(FLAGS_graph_file, nbins, bins)) {
    printf("Can't write graph data\n");
    return 1;
  }

  int16_t diffs2[num_samples];
  zero_int16_array(num_samples, diffs2);
  if (!calculate_second_differences(num_samples, diffs, diffs2)) {
    printf("Can't calculate second differences\n");
    return 1;
  }

  if (FLAGS_print_bins) {
    printf("Second differences\n");
    print_int16_array(num_samples, diffs2);
    printf("\n");
  }

  double mean2 = calculate_int16_mean(num_samples - 1, diffs2);
  double var2 = calculate_int16_variance(num_samples - 1, diffs2, mean2);
  double sigma2 = sqrt(var2);
  printf("Second differences, mean: %5.3lf, variance: %6.3lf, sigma: %6.3lf\n", mean2, var2, sigma2);
  uint32_t signed_bins[2 * nbins];
  zero_uint32_array(2 * nbins, signed_bins);

  for (int i = 0; i < (num_samples - 1); i++) {
    signed_bins[diffs2[i] + (1<<num_bits) - 1]++;
  }
  double second_shannon_entropy, second_renyi_entropy, second_min_entropy;
  if (!calculate_bin_entropies(num_samples - 1, 2 * nbins, signed_bins, &second_shannon_entropy,
          &second_renyi_entropy, &second_min_entropy)) {
    printf("Can't calculate second entropies\n");
    return 1;
  }
  printf("Second shannon entropy: %5.3lf, second renyi entropy: %5.3lf, second min entropy: %5.3lf\n\n", 
        second_shannon_entropy, second_renyi_entropy, second_min_entropy);
  if (!write_graph_data(FLAGS_second_graph_file, 2* nbins, signed_bins)) {
    printf("Can't write graph data\n");
    return 1;
  }

  if (FLAGS_do_conditional) {
    uint32_t base_bin = 0;
    int num_conditional_samples = 0;
    uint32_t cond_bins[nbins];

    for (base_bin = 0; base_bin < nbins; base_bin++) {
      num_conditional_samples = 0;
      if (!bin_conditional_data(num_samples, diffs, nbins, cond_bins, base_bin)) {
        printf("Can't get conditional bins\n");
        return 1;
      }
      for (int i = 0; i < nbins; i++)
        num_conditional_samples += cond_bins[i];
 
      if (FLAGS_print_bins) { 
        printf("\nconditional bins based on %u:\n", base_bin);
        print_uint32_array(nbins, cond_bins);
        printf("\n");
      }

      double conditional_shannon_entropy = 0.0;
      double conditional_renyi_entropy = 0.0;
      double conditional_min_entropy = 0.0;
      if (!calculate_bin_entropies(num_conditional_samples, nbins, cond_bins, &conditional_shannon_entropy,
            &conditional_renyi_entropy, &conditional_min_entropy)) {
        printf("Can't calculate entropies\n");
        return 1;
      }
      printf("Conditional entropy, prior: %2u, shannon: %5.3lf, renyi: %5.3lf, min: %5.3lf\n", 
            base_bin, conditional_shannon_entropy, conditional_renyi_entropy, conditional_min_entropy);
    }
  }

  close_crypto();
  printf("\ndone\n");
  return 0;
}
