// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: test_jitter_collection.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "entropy_collection.h"
#include "probability_support.h"
#include "aes.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");
DEFINE_string(graph_file_name, "jitter.bin", "jitter file");
DEFINE_int32(num_samples, 100, "number of samples");
DEFINE_int32(num_loops, 5, "number of loops in test_code");
DEFINE_int32(test_set, 1, "test set");

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wunknown-pragmas"

#pragma GCC push_options
#pragma GCC optimize ("O0")
// nuc has 32Kb L1 i-cache, and 32KB L1 d-cache, should adjust to 
// flush d cache from timet to time

volatile void inline test_code_1(int num_loops) {
  volatile int  t = 0;

  for (int i = 0; i < num_loops; i++) {
    t += i;
  }
  t /= 2;
}

const int d_buf_size = 64000;
volatile void inline test_code_2(int num_loops, int size_buf, byte* buf) {
  int index = size_buf / num_loops;

  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < num_loops; i++) {
      buf[i * index] += 1;
    }
  }
}

#pragma GCC pop_options

int pick_num_bins(int num_samples,  uint32_t* delta_array) {
  int largest = 0;
  int smallest = num_samples;
  int total = 0;
  double mean = 0.0;

  for (int i = 0; i < num_samples; i++) {
    if (delta_array[i] > largest)
      largest = delta_array[i];
    if (delta_array[i] < smallest)
      smallest= delta_array[i];
    mean += (double)delta_array[i];
    total++;
  }
  if (total <= 0)
    return 1;
  mean /= ((double) total);
  double adjusted_mean = mean - ((double)largest) / ((double) total);

  printf("largest: %d, smallest: %d, total non-zero: %d, mean: %lf, adjusted mean: %lf\n",
         largest, smallest, total, mean, adjusted_mean);

  int spread = (int)mean - smallest;
  return (int)adjusted_mean + spread + 1;
}

bool pick_bin_bounds(int num_samples, int nbins, uint32_t* bins, int* lower_bin, int* upper_bin) {
  int sig_level = num_samples / 100;
  for (*upper_bin = (nbins - 1); *upper_bin >= 0 ; (*upper_bin)--) {
    if (bins[*upper_bin] >= sig_level)
      break;
  }
  for (*lower_bin = 0; *lower_bin < *upper_bin; (*lower_bin)++) {
    if (bins[*lower_bin] >= sig_level)
      break;
  }

  if (*lower_bin > 5)
    *lower_bin -= 2;
  if (*upper_bin < (nbins - 5))
    *upper_bin += 2;
  return true;
}

bool test_jitter1(int num_samples, int num_loops) {
  uint64_t cpc = calibrate_rdtsc();

  if (FLAGS_print_all) {
    printf ("%lld cpc\n\n", cpc);
  }

  uint64_t t1, t2;
  uint32_t delta;
  uint32_t delta_array[num_samples];
  
  byte buf[d_buf_size];
  if (FLAGS_test_set == 1) {
    for (int i = 0; i < num_samples; i++) {
      t1 = read_rdtsc();
      test_code_1(num_loops);
      t2 = read_rdtsc();
      delta = t2 - t1;
      delta_array[i] = delta / 2;
    }
  } else {
    for (int i = 0; i < num_samples; i++) {
      t1 = read_rdtsc();
      test_code_2(num_loops, d_buf_size, buf);
      t2 = read_rdtsc();
      delta = t2 - t1;
      delta_array[i] = delta / 2;
    }
  }

  if (FLAGS_print_all) {
    printf("test set: %d\n", FLAGS_test_set);
    printf("delta_array:\n");
    print_uint32_array(num_samples, delta_array);
    printf("\n");
  }

  int nbins = pick_num_bins(num_samples,  delta_array);
  if (nbins < 0)
    return false;
  uint32_t bins[nbins];
  if (!bin_raw_data(num_samples, delta_array, nbins, bins)) {
    printf("Can't bin data\n");
    return false;
  }

  int upper_bin;
  int lower_bin;
  if (!pick_bin_bounds(num_samples, nbins, bins, &lower_bin, &upper_bin)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("%d bins, lower %d, upper: %d\n", nbins, lower_bin, upper_bin);
  }

  if (FLAGS_print_all) {
    printf("bins from %d to %d selected:\n", lower_bin, upper_bin);
    print_uint32_array(1 + upper_bin - lower_bin, &bins[lower_bin]);
    printf("\n");
  }

  double p[nbins];
  double expected = 0.0;
  for (int i = 0; i < nbins; i++) {
    p[i] = ((double)bins[i]) / ((double) num_samples);
    expected += p[i] * ((double) i);
  }

  if (FLAGS_print_all) {
    int k = 0;
    printf("probabilities:\n");
    for (int i = lower_bin;  i < upper_bin; i++) {
      if (p[i] <= 0.0)
        continue;
      printf("%03d, %4.3lf;  ", i, p[i]);
      if (((k++)%8) == 7)
        printf("\n");
    }
    printf("\n\n");
  }

  double sh_ent = shannon_entropy(nbins, p);
  double ren_ent = renyi_entropy(nbins, p);
  double min_ent = min_entropy(nbins, p);
  printf("Samples: %d, num_loops: %d, Expected bin: %5.3lf\n", num_samples, num_loops, expected);
  printf("   Shannon entropy: %6.4lf, renyi entropy: %6.4lf, min_entropy: %6.4lf\n",
          sh_ent, ren_ent, min_ent);

  double x[nbins];
  double y[nbins];
  for (int i = 0; i < nbins; i++) {
    x[i] = (double) i;
    y[i] = (double) bins[i];
  }

  if (!write_general_graph_data(FLAGS_graph_file_name, upper_bin - lower_bin,
                                &x[lower_bin], &y[lower_bin])) {
    printf("Can't write graph data\n");
    return false;
  }
  return true;
}


TEST (jitter, test_jitter) {
  EXPECT_TRUE(test_jitter1(FLAGS_num_samples, FLAGS_num_loops));
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  init_crypto();

  int result = RUN_ALL_TESTS();

  close_crypto();
  printf("\n");
  return result;
}
