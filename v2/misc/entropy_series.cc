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
#include "entropy_support.h"

DEFINE_bool(debug, true, "Debug flag");
DEFINE_bool(do_conditional, false, "Analyze conditional entropy");
DEFINE_bool(print_bins, false, "Print bins");
DEFINE_string(num_samples, "1000", "number of samples");
DEFINE_string(interval, "1000", "interval in us");
DEFINE_string(output_file, "tick_difference_output.bin", "output file");
DEFINE_string(graph_file, "graph.bin", "graph output file");

// entropy series generates time series differences
int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  if (!init_crypto()) {
    printf("init_crypto failed\n");
    return 1;
  }

  int interval, num_samples;
  sscanf(FLAGS_interval.c_str(), "%d", &interval);
  sscanf(FLAGS_num_samples.c_str(), "%d", &num_samples);
  uint64_t num_ticks_per_sec = calibrate_rdtsc();
  int num_bits = 6;
  int divisor = 2;
  printf("\ninterval: %d us, samples: %d, ticks/second: %lu, num_bits: %d, bins: %d, divisor: %d\n", 
    interval, num_samples, num_ticks_per_sec, num_bits, 1<<num_bits, divisor);

  uint32_t diffs[num_samples];
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

  double mean = calculate_mean(num_samples, diffs);
  double var = calculate_variance(num_samples, diffs, mean);
  double sigma = sqrt(var);
  printf("mean: %8.3lf, variance: %8.3lf, sigma: %8.3lf\n", mean, var, sigma);

  int nbins = 1<<6;
  uint32_t bins[nbins];
  if (!bin_raw_data(num_samples, diffs, nbins, bins)) {
    printf("Can't bin data\n");
    return 1;
  }

  if (FLAGS_print_bins) {
    printf("\nbins:\n");
    print_uint32_array(nbins, bins);
    printf("\n");
  }

  double shannon_entropy = 0.0;
  double renyi_entropy = 0.0;
  double min_entropy = 0.0;
  if (!calculate_entropies(num_samples, nbins, bins, &shannon_entropy,
        &renyi_entropy, &min_entropy)) {
    printf("Can't calculate entropies\n");
    return 1;
  }
  printf("shannon entropy: %5.3lf, renyi entropy: %5.3lf, min entropy: %5.3lf\n", 
        shannon_entropy, renyi_entropy, min_entropy);

  double normal_dist_ent = (.5 * (1.0 + log(2.0 * var * 3.14159))) / log(2.0);
  printf("Normal distribution estimate: %8.3lf\n", normal_dist_ent);
  printf("\n");

  if (!write_graph_data(FLAGS_graph_file, nbins, bins)) {
    printf("Can't write graph data\n");
    return 1;
  }

  if (FLAGS_do_conditional) {
    uint32_t base_bin = 0;
    int num_conditional_samples = 0;
    uint32_t cond_bins[nbins];

    for (base_bin = 0; base_bin < 64; base_bin++) {
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
      if (!calculate_entropies(num_conditional_samples, nbins, cond_bins, &conditional_shannon_entropy,
            &conditional_renyi_entropy, &conditional_min_entropy)) {
        printf("Can't calculate entropies\n");
        return 1;
      }
      printf("Conditional entropies, prior: %2u, shannon: %5.3lf, renyi: %5.3lf, min: %5.3lf\n", 
            base_bin, conditional_shannon_entropy, conditional_renyi_entropy, conditional_min_entropy);
    }
  }

  close_crypto();
  printf("\ndone\n");
  return 0;
}
