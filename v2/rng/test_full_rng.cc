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
// File: test_full_rng.cc

#include <gflags/gflags.h>

#include <stdio.h>
#include "crypto_support.h"
#include "probability_support.h"
#include "entropy_accumulate.h"
#include "entropy_source.h"
#include "hash_drng.h"

DEFINE_bool(print_all, false, "Print intermediate test computations");
DEFINE_int32(pool_size, 4096, "pool size");
DEFINE_double(entropy_required, 256, "entropy required");

#pragma GCC push_options
#pragma GCC optimize ("O0")
// nuc has 32Kb L1 i-cache, and 32KB L1 d-cache, should adjust to 
// flush d cache from timet to time

volatile void inline test_code_1(int num_loops) {
  volatile int  t = 0;

  for (int i = 0; i < num_loops; i++) {
    t += i * 6;
  }
  t /= 2;
  usleep(122);
}

#pragma GCC pop_options

int sw_entropy(int num_samples, byte* sample) {
  uint64_t t1, t2;
  uint32_t delta;

  for (int i = 0; i < num_samples; i++) {
    t1 = read_rdtsc();
    test_code_1(11);
    t2 = read_rdtsc();
    delta = t2 - t1;
    sample[i] = (byte)delta;
  }
  return num_samples;
}

int hw_entropy(int num_samples, byte* sample) {
  uint32_t out = 0;
  int n = 0;
  int k = 0;

  while (n < num_samples) {
    k = num_samples - sizeof(uint32_t);
    if (k > 4)
      k = 4;
    asm volatile(
      "\trdrand %%edx\n"
      "\tmovl   %%edx, %[out]\n"
    : [out] "=m"(out)::"%edx");
  memcpy(&sample[n], (byte*)&out, k);
  n += k;
  }

  return n;
}

int get_intel_rand(int n, byte* sample) {
  return n;
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  entropy_source hw_source("Intel RNG", 7.5, hw_entropy);   // hardware source
  entropy_source sw_source("jitter", 1.0, sw_entropy);      // software source
  entropy_accumulate the_accumulator;                       // The accumulator
  hash_drng the_drng;                                       // DRBG

  init_crypto();

  int size_sample_buf = 128;
  byte sample_buf[size_sample_buf];
  int sample_size = 40;
  
  memset(sample_buf, 0, size_sample_buf);

  double required_entropy = 256.0;

  // add 256 hw bits
  while (the_accumulator.entropy_estimate() < required_entropy) {
    if (hw_source.getentropy_(sample_size, sample_buf) < sample_size) {
      printf("HW RNG returned fewer bytes\n");
    }
#if 1
    printf("HW ent: ");
    print_bytes(sample_size, sample_buf);
#endif
    the_accumulator.add_samples(sample_size, sample_buf, hw_source.ent_per_sample_byte_);
  }

  if (FLAGS_print_all) {
    printf("Entropy after HW: %lf\n", the_accumulator.entropy_estimate());
  }

  // add 384 sw bits
  required_entropy = 384.0;
  sample_size = 20;
  while (the_accumulator.entropy_estimate() < required_entropy) {
    if (sw_source.getentropy_(sample_size, sample_buf) < sample_size) {
      printf("SW RNG returned fewer bytes\n");
    }
#if 1
    printf("SW ent: ");
    print_bytes(sample_size, sample_buf);
#endif
    the_accumulator.add_samples(sample_size, sample_buf, hw_source.ent_per_sample_byte_);
  }

  if (FLAGS_print_all) {
    printf("Entropy after SW: %lf\n", the_accumulator.entropy_estimate());
  }

  // set up drng
  int seed_size= 64;
  byte seed[64];
  double entropy_of_seed = 0.0;
  memset(seed, 0, seed_size);

  if (!the_accumulator.empty_pool(&seed_size, seed, &entropy_of_seed)) {
    printf("can't empty accumulator pool\n");
    return 0;
  }

  if (FLAGS_print_all) {
    printf("Entropy from empty pool: %lf\n", entropy_of_seed);
  }

  if (entropy_of_seed < 384.0) {
    printf("seed entropy too small\n");
    return 0;
  }
  entropy_of_seed = 256.0;

  if (FLAGS_print_all) {
    printf("\nseed: ");
    print_bytes(seed_size, seed);
    printf("\n");
  }

  if (!the_drng.init(0, nullptr, 0, nullptr, seed_size, seed, entropy_of_seed)) {
    printf("can't initialize drng\n");
    return 0;
  }

  int size_random_numbers = 32;
  byte random_numbers[64];
  memset(random_numbers, 0, 64);

  // fetch random numbers
  for (int j = 0; j < 10; j++) {
    if (!the_drng.generate_random_bits(8 * size_random_numbers, random_numbers, 0, nullptr)) {
      printf("can't generate random bits\n");
      return 0;
    }
    printf("random number %d: ", j);
    print_bytes(size_random_numbers, random_numbers);
  }

  close_crypto();
  printf("\n");

  return 0;
}
