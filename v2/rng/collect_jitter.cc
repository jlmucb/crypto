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

#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "entropy_collection.h"
#include "probability_support.h"
#include "aes.h"
#include "sha3.h"


DEFINE_bool(print_all, false, "delta computations");
DEFINE_string(sample_file_name, "", "sample file");
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


void print_prob(int n, double* p) {
  int i = 0;
  while (p[i] < 0.0002 &&  i < n)
    i++;
  int m = n - 1;
  while (p[m] < 0.0002 && m >= 0)
    m--;

  int np = 0;
  for(; i <= m; i++) {
    printf("p[%3d]= %5.3lf  ", i, p[i]);
    if (++np >= 6) {
      printf("\n");
      np = 0;
    }
  }
  if (np > 0)
    printf("\n");
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);

  init_crypto();

  uint64_t cpc = calibrate_rdtsc();
  uint64_t t1, t2;
  uint64_t delta;

  const char* jitter_block_description[5] = {
    "Simple jitter test 0",
    "Simple jitter test 1",
    "Simple jitter test 2",
    "Memory jitter test",
    "Hash jitter test",
  };
  
  byte sample_buf[FLAGS_num_samples];
  if (FLAGS_test_set == 0) {
    for (int i = 0; i < FLAGS_num_samples; i++) {
      t1 = read_rdtsc();
      simple_jitter_block_0(FLAGS_num_loops);
      t2 = read_rdtsc();
      delta = t2 - t1;
      sample_buf[i] = (byte) ((delta / 2) & 0xff);
    }
  } else if (FLAGS_test_set == 1) {
    for (int i = 0; i < FLAGS_num_samples; i++) {
      t1 = read_rdtsc();
      simple_jitter_block_1(FLAGS_num_loops);
      t2 = read_rdtsc();
      delta = t2 - t1;
      sample_buf[i] = (byte) ((delta / 2) & 0xff);
    }
  } else if (FLAGS_test_set == 2) {
    byte buf[SIZE_L1];
    for (int i = 0; i < FLAGS_num_samples; i++) {
      t1 = read_rdtsc();
      simple_jitter_block_2(FLAGS_num_loops, SIZE_L1, buf);
      t2 = read_rdtsc();
      delta = t2 - t1;
      sample_buf[i] = (byte) ((delta / 2) & 0xff);
    }
  } else if (FLAGS_test_set == 3) {
    byte buf_mem[SIZE_L1];
    memset(buf_mem, 0, SIZE_L1);
    for (int i = 0; i < FLAGS_num_samples; i++) {
      t1 = read_rdtsc();
      memory_jitter_block(FLAGS_num_loops, SIZE_L1, buf_mem);
      t2 = read_rdtsc();
      delta = t2 - t1;
      sample_buf[i] = (byte) ((delta / 2) & 0xff);
    }
  } else if (FLAGS_test_set == 4) {
    byte buf_hash[SIZE_HASH_BUF];
    for (int i = 0; i < SIZE_HASH_BUF; i++)
      buf_hash[i] = i;
    for (int i = 0; i < FLAGS_num_samples; i++) {
      t1 = read_rdtsc();
      hash_jitter_block(FLAGS_num_loops, SIZE_HASH_BUF, buf_hash);
      t2 = read_rdtsc();
      delta = t2 - t1;
      sample_buf[i] = (byte) ((delta / 2) & 0xff);
    }
  } else {
    printf("unknown test\n");
    return 1;
  }

  if (FLAGS_print_all) {
    printf("%s, cpc: %ld\n", jitter_block_description[FLAGS_test_set], cpc);
  }

  if (FLAGS_sample_file_name == "") {
    printf("Must have sample file\n");
    return 1;
  }
  if (!write_raw_byte_data(FLAGS_sample_file_name, FLAGS_num_samples, sample_buf)) {
     printf("Can't write byte file\n");
    return 1;
   }

  int num_samples = FLAGS_num_samples;
  int count[256];
  double p[256];
  int max = 0;
  int min = 256;
  int max_index = 0;
  int min_index = 0;

  for (int i = 0; i < 256; i++)
    count[i] = 0;
  for (int i = 0; i < num_samples; i++)
    count[sample_buf[i]]++;
  for (int i = 0; i < 256; i++) {
    if (count[i] == 0)
      continue;
    if (max < count[i]) {
      max = count[i];
      max_index = i;
    }
    if (min > count[i]) {
      min = count[i];
      min_index = i;
    }
  }
  for (int i = 0; i < 256; i++)
    p[i] = ((double) count[i]) / ((double) num_samples);

  if (FLAGS_print_all) {
    print_prob(256, p);
  }

  double expected = 0.0;
  double t = 0.0;
  for (int i = 0; i < 256; i++) {
    t = ((double)i) * p[i];
    expected += t;
  }

  double variance = 0.0;
  for (int i = 0; i < 256; i++) {
    t = ((double)i) * p[i] - expected;
    variance += t * t * p[i];
  }
  double sigma = sqrt(variance);
  printf("num samples: %d, min index: %d, min: %d, max index: %d, max: %d\n",
    num_samples, min_index, min, max_index, max);
  printf("num samples: %d, expected: %lf, variance: %lf, sigma: %lf\n",
    num_samples, expected, variance, sigma);

  double sh_ent = shannon_entropy(256, p);
  double ren_ent = renyi_entropy(256, p);
  double min_ent = min_entropy(256, p);
  printf("   Shannon entropy: %6.3lf, renyi entropy: %6.3lf, min_entropy: %6.3lf\n",
          sh_ent, ren_ent, min_ent);

  close_crypto();
  printf("\n");
  return 0;
}
