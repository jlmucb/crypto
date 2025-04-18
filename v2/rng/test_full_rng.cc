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
#include "sha3.h"
#include "health_tests.h"

DEFINE_bool(print_all, false, "Print intermediate test computations");
DEFINE_int32(pool_size, 4096, "pool size");
DEFINE_double(entropy_required, 256, "entropy required");

#pragma GCC push_options
#pragma GCC optimize ("O0")
// nuc has 32Kb L1 i-cache, and 32KB L1 d-cache, should adjust to 
// flush d cache from time to time

// simple example
volatile void inline simple_jitter_block(int num_loops) {
  volatile int  t = 0;

  for (int i = 0; i < num_loops; i++) {
    t += i * 6;
  }
  t /= 2;
  usleep(122);
}

// Memory access
const int SIZE_L1 = 32<<10;  // changes on different cpus
// size should be bigger than SIZE_L1
volatile void inline memory_jitter_block(int num_loops, int size, byte* buf) {
  int inc = size / 100;
  if (inc <= 0)
    inc = 1;
  for (int i = 0; i < num_loops; i++) {
    for (int j = 0; j < size; j+=inc) {
      buf[j] += 1;
    }
  }
}

// hash timing
volatile void inline hash_jitter_block(int num_loops, int size, byte* to_hash) {
  sha3 hash_obj;

  for (int i = 0; i < num_loops; i++) {
    hash_obj.init(1024);
    hash_obj.add_to_hash(size, to_hash);
    hash_obj.finalize();
  }
}

int sw_entropy(int num_samples, byte_t* sample) {
  uint64_t t1, t2;
  uint32_t delta;

  for (int i = 0; i < num_samples; i++) {
    t1 = read_rdtsc();
    simple_jitter_block(11);
    t2 = read_rdtsc();
    delta = (t2 - t1) / 2;    // bottom bit is always 0 on some machines
    sample[i] = (byte_t)delta;
  }
  return num_samples;
}

#pragma GCC pop_options

int hw_entropy(int num_samples, byte_t* sample) {
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
  memcpy(&sample[n], (byte_t*)&out, k);
  n += k;
  }

  return n;
}

int get_intel_rand(int n, byte_t* sample) {
  return n;
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

#if 0
  int n_in = 32 * 8;
  int nw = 256;
  int n_out = 256;
  double h_in = .9  * n_in;
  double h_out;
  h_out = entropy_estimate_from_samples(n_in, n_out, nw, h_in);
  printf("n_in: %d, nw: %d, n_out: %d, h_in: %lf, h_out: %lf\n",
          n_in, nw, n_out, h_in, h_out);

  n_in = 64 * 8;
  h_in = .9 * n_in;
  h_out = entropy_estimate_from_samples(n_in, n_out, nw, h_in);
  printf("n_in: %d, nw: %d, n_out: %d, h_in: %lf, h_out: %lf\n",
          n_in, nw, n_out, h_in, h_out);

  n_in = 128 * 8;
  h_in = .9 * n_in;
  h_out = entropy_estimate_from_samples(n_in, n_out, nw, h_in);
  printf("n_in: %d, nw: %d, n_out: %d, h_in: %lf, h_out: %lf\n",
          n_in, nw, n_out, h_in, h_out);
#endif

  entropy_source hw_source("Intel RNG", 7.5, hw_entropy);   // hardware source
  entropy_source sw_source("jitter", 1.0, sw_entropy);      // software source
  entropy_accumulate  hw_accumulator;                       // The accumulator
  entropy_accumulate  sw_accumulator;                       // The accumulator
  hash_drng the_drng;                                       // DRBG
  hash_drng hw_drng;                                        // DRBG
  hash_drng sw_drng;                                        // DRBG
  int size_random_numbers = 64;
  byte_t random_numbers[4*size_random_numbers];
  int seed_size= 64;
  byte_t seed[4 * seed_size];
  double entropy_of_seed = 0.0;
  int size_sample_buf = 128;
  byte_t sample_buf[size_sample_buf];
  int sample_size =  32;
  double required_entropy = 256.0;
  apt apt_health;
  rct rct_health;

  if (!init_crypto()) {
    return true;
  }

  // hw source
  if (FLAGS_print_all) {
    printf("\n\nHardware test\n");
  }
  memset(sample_buf, 0, size_sample_buf);
  apt_health.init();
  rct_health.init();
  while (hw_accumulator.entropy_estimate() < required_entropy) {
    if (hw_source.getentropy_(sample_size, sample_buf) < sample_size) {
      printf("HW RNG returned fewer bytes\n");
    }
    if (FLAGS_print_all) {
      printf("HW noise : ");
      print_bytes(sample_size, sample_buf);
    }

    for (int i = 0; i < sample_size; i++) {
      apt_health.insert((uint32_t)sample_buf[i]);
      rct_health.insert((uint32_t)sample_buf[i]);
    }
    if (apt_health.failed())
      printf("apt health test failed\n");
    if (rct_health.failed())
      printf("rct health test failed\n");
    hw_accumulator.add_samples(sample_size, sample_buf, hw_source.ent_per_sample_byte_);
  }

  // set up drng for hw #'s
  entropy_of_seed = 0.0;
  memset(seed, 0, seed_size);
  if (!hw_accumulator.empty_pool(&seed_size, seed, &entropy_of_seed)) {
    printf("can't empty accumulator pool\n");
    return 0;
  }
  if (FLAGS_print_all) {
    printf("Entropy from empty pool: %lf\n", entropy_of_seed);
  }
  if (entropy_of_seed < required_entropy) {
    printf("seed entropy too small\n");
    return 0;
  }

  if (FLAGS_print_all) {
    printf("seed: ");
    print_bytes(seed_size, seed);
    printf("\n");
  }

  if (!hw_drng.init(0, nullptr, 0, nullptr, seed_size, seed, entropy_of_seed)) {
    printf("can't initialize drng\n");
    return 0;
  }
  memset(random_numbers, 0, 64);
  printf("Hardware derived random numbers:\n");
  for (int j = 0; j < 10; j++) {
    if (!hw_drng.generate_random_bits(8 * size_random_numbers, random_numbers, 0, nullptr)) {
      printf("can't generate random bits\n");
      return 0;
    }
    printf("  random number %d: ", j);
    print_bytes(size_random_numbers, random_numbers);
  }

  // add sw bits
  if (FLAGS_print_all) {
    printf("\n\nSoftware test\n");
  }

  memset(sample_buf, 0, size_sample_buf);
  apt_health.init();
  rct_health.init();
  sample_size = 32;
  entropy_of_seed = 0.0;
  while (sw_accumulator.entropy_estimate() < required_entropy) {
    if (sw_source.getentropy_(sample_size, sample_buf) < sample_size) {
      printf("SW RNG returned fewer bytes\n");
    }
    if (FLAGS_print_all) {
      printf("SW noise: ");
      print_bytes(sample_size, sample_buf);
    }
    sw_accumulator.add_samples(sample_size, sample_buf, sw_source.ent_per_sample_byte_);
    for (int i = 0; i < sample_size; i++) {
      apt_health.insert((uint32_t)sample_buf[i]);
      rct_health.insert((uint32_t)sample_buf[i]);
    }
    if (apt_health.failed())
      printf("apt health test failed\n");
    if (rct_health.failed())
      printf("rct health test failed\n");
  }

  // set up drng for sw #'s
  entropy_of_seed = 0.0;
  memset(seed, 0, seed_size);
  if (!sw_accumulator.empty_pool(&seed_size, seed, &entropy_of_seed)) {
    printf("can't empty accumulator pool\n");
    return 0;
  }
  if (FLAGS_print_all) {
    printf("Entropy from empty pool: %lf\n", entropy_of_seed);
  }
  if (entropy_of_seed < required_entropy) {
    printf("seed entropy too small\n");
    return 0;
  }
  if (FLAGS_print_all) {
    printf("seed: ");
    print_bytes(seed_size, seed);
    printf("\n");
  }

  if (!sw_drng.init(0, nullptr, 0, nullptr, seed_size, seed, entropy_of_seed)) {
    printf("can't initialize drng\n");
    return 0;
  }
  memset(random_numbers, 0, 64);
  printf("Software derived random numbers:\n");
  for (int j = 0; j < 10; j++) {
    if (!sw_drng.generate_random_bits(8 * size_random_numbers, random_numbers, 0, nullptr)) {
      printf("can't generate random bits\n");
      return 0;
    }
    printf("  random number %d: ", j);
    print_bytes(size_random_numbers, random_numbers);
  }

  close_crypto();
  printf("\n");

  return 0;
}
