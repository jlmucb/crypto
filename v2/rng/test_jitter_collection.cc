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
#include "sha3.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");
DEFINE_bool(print_all2, false, "Print delta computations");
DEFINE_string(sample_file_name, "", "sample file");
DEFINE_string(graph_file_name, "jitter.bin", "jitter file");
DEFINE_int32(num_samples, 100, "number of samples");
DEFINE_int32(num_loops, 5, "number of loops in test_code");
DEFINE_int32(test_set, 1, "test set");

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wunknown-pragmas"

#pragma GCC push_options
#pragma GCC optimize ("O0")
// nuc has 32Kb L1 i-cache, and 32KB L1 d-cache, should adjust to 
// flush d cache from time to time

// simple example
volatile void inline simple_jitter_block_0(int num_loops) {
  volatile int  t = 0;

  for (int i = 0; i < num_loops; i++) {
    t += i * 6;
  }
  t /= 2;
  //usleep(2);
}

volatile void inline simple_jitter_block_1(int num_loops) {
  volatile int  t = 0;

  for (int i = 0; i < num_loops; i++) {
    t += i;
  }
  t /= 2;
}

const int d_buf_size = 64<<10;
volatile void inline simple_jitter_block_2(int num_loops, int size_buf, byte* buf) {
  int index = size_buf / num_loops;

  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < num_loops; i++) {
      buf[i * index] += 1;
    }
  }
}

// Memory access
const int SIZE_L1 = 32<<10;  // changes on different cpus
int mem_shift = 0;
// size should be bigger than SIZE_L1
volatile void inline memory_jitter_block(int num_loops, int size, byte* buf) {
  mem_shift++;
  int inc = size / 100;
  if (inc == 0)
    inc= 1;
  for (int i = 0; i < num_loops; i++) {
    for (int j = 0; j < size; j+=inc) {
      buf[(mem_shift + j) % size] += 1;
    }
  }
}

// hash timing
const int SIZE_HASH_BUF = 128;
volatile void inline hash_jitter_block(int num_loops, int size, byte* to_hash) {
  sha3 hash_obj(1024);

  for (int i = 0; i < num_loops; i++) {
    hash_obj.init();
    hash_obj.add_to_hash(size, to_hash);
    hash_obj.finalize();
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

  printf("largest: %d, smallest: %d, non-zero: %d, mean: %6.3lf, adjusted mean: %6.3lf\n",
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

bool test_jitter(int num_samples, int num_loops) {
  uint64_t cpc = calibrate_rdtsc();
  uint64_t t1, t2;
  uint32_t delta;
  uint32_t delta_array[num_samples];

  const char* jitter_block_description[5] = {
    "Simple jitter test 0",
    "Simple jitter test 1",
    "Simple jitter test 2",
    "Memory jitter test",
    "Hash jitter test",
  };
  
  byte buf[d_buf_size];
  if (FLAGS_test_set == 0) {
    for (int i = 0; i < num_samples; i++) {
      t1 = read_rdtsc();
      simple_jitter_block_0(num_loops);
      t2 = read_rdtsc();
      delta = t2 - t1;
      delta_array[i] = (delta / 2) & 0xff;
    }
  } else if (FLAGS_test_set == 1) {
    for (int i = 0; i < num_samples; i++) {
      t1 = read_rdtsc();
      simple_jitter_block_1(num_loops);
      t2 = read_rdtsc();
      delta = t2 - t1;
      delta_array[i] = (delta / 2) & 0xff;
    }
  } else if (FLAGS_test_set == 2) {
    for (int i = 0; i < num_samples; i++) {
      t1 = read_rdtsc();
      simple_jitter_block_2(num_loops, d_buf_size, buf);
      t2 = read_rdtsc();
      delta = t2 - t1;
      delta_array[i] = (delta / 2) & 0xff;
    }
  } else if (FLAGS_test_set == 3) {
    byte buf_mem[SIZE_L1];
    memset(buf_mem, 0, SIZE_L1);
    for (int i = 0; i < num_samples; i++) {
      t1 = read_rdtsc();
      memory_jitter_block(num_loops, SIZE_L1, buf_mem);
      t2 = read_rdtsc();
      delta = t2 - t1;
      delta_array[i] = (delta / 2) & 0xff;
    }
  } else if (FLAGS_test_set == 4) {
    byte buf_hash[SIZE_HASH_BUF];
    for (int i = 0; i < SIZE_HASH_BUF; i++)
      buf_hash[i] = i;
    for (int i = 0; i < num_samples; i++) {
      t1 = read_rdtsc();
      hash_jitter_block(num_loops, SIZE_HASH_BUF, buf_hash);
      t2 = read_rdtsc();
      delta = t2 - t1;
      delta_array[i] = (delta / 2) & 0xff;
    }
  } else {
    printf("unknown test\n");
    return 1;
  }

  if (FLAGS_print_all) {
    printf("%s, cpc: %ld\n", jitter_block_description[FLAGS_test_set], cpc);
  }

  if (FLAGS_print_all2) {
    printf("\ndelta_array:\n");
    print_uint32_array(num_samples, delta_array);
    printf("\n");
  }

  if (FLAGS_sample_file_name != "") {
    byte sample_buf[num_samples];
    for (int i = 0; i < num_samples; i++)
      sample_buf[i] = (byte)delta_array[i];
    if (!write_raw_byte_data(FLAGS_sample_file_name, num_samples, sample_buf)) {
      printf("Can't write byte file\n");
    }
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
    printf("%d bins, lower %d, upper: %d, ", nbins, lower_bin, upper_bin);
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

  double variance = 0.0;
  double t= 0.0;
  for (int i = 0; i < nbins; i++) {
    t = ((double)i) * p[i] - expected;
    variance += t * t * p[i];
  }

  if (FLAGS_print_all) {
    int k = 0;
    printf("Samples: %d, num_loops: %d, Expected bin: %6.3lf, deviation: %6.3lf\n", 
    num_samples, num_loops, expected, sqrt(variance));
    printf("probabilities:\n");
    for (int i = lower_bin;  i < upper_bin; i++) {
      if (p[i] <= 0.0)
        continue;
      printf("%3d,%4.3lf; ", i, p[i]);
      if (((k++)%8) == 7)
        printf("\n");
    }
    printf("\n");
  }

  double sh_ent = shannon_entropy(nbins, p);
  double ren_ent = renyi_entropy(nbins, p);
  double min_ent = min_entropy(nbins, p);
  printf("   Shannon entropy: %6.3lf, renyi entropy: %6.3lf, min_entropy: %6.3lf\n",
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
  EXPECT_TRUE(test_jitter(FLAGS_num_samples, FLAGS_num_loops));
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
