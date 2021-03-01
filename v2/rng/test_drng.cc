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
// File: test_drng.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "drng.h"
#include "probability_support.h"
#include "aes.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");


bool test_ctr_drng() {
  byte ent_bytes[512];
  byte bytes_out[512];
  memset(ent_bytes, 0, 512);
  memset(bytes_out, 0, 512);
 
  hash_drng obj;
  obj.set_policy(256, 1024, 200);

  for(int i = 0; i < 512; i++)
    ent_bytes[i] = i % 4;
  obj.add_entropy(512, ent_bytes, 256); 

  if (!obj.init(0, nullptr, 0, nullptr)) {
    printf("cannot init object\n");
    return false;
  }

  // reinit pool for reseed
  for(int i = 0; i < 384; i++)
    ent_bytes[i] = i % 2;
  obj.add_entropy(384, ent_bytes, 256); 

  if (FLAGS_print_all) {
    printf("\n");
    printf("initialized_: %d\n", obj.initialized_);
    printf("reseed_ctr_: %d\n", obj.reseed_ctr_);
    printf("int reseed_interval: %d\n", obj.reseed_interval_);
    printf("num_entropy_bits_present: %d\n", obj.num_entropy_bits_present_);
    printf("num_ent_bits_required: %d\n", obj.num_ent_bits_required_);
    printf("current_entropy_in_pool: %d\n", obj.current_entropy_in_pool_);
    printf("current_size_pool: %d\n", obj.current_size_pool_);
    printf("pool_size_: %d\n", obj.pool_size_);
    printf("hash_byte_output_size: %d\n", obj.hash_byte_output_size_);
    printf("seed_len_bits: %d\n", obj.seed_len_bits_);
    printf("seed_len_bytes: %d\n", obj.seed_len_bytes_);
    printf("\n");
  }

  for (int j = 0; j < 5; j++) {
    if (!obj.generate(256, bytes_out, 0, nullptr)) {
      printf("cannot generate bits\n");
      return false;
    }
    if (FLAGS_print_all) {
      printf("generated: ");
      print_bytes(32, bytes_out);
      // printf("\n");
    }
  }

  printf("\n");
  return true;
}

bool test_markov() {
  const int seq_len = 4;
  byte seq[seq_len + 8];
  int num_seq = 1 << seq_len;

  byte b;
  double p_0 = .5;
  double p_1 = .5;
  double p_00 = .5;
  double p_01 = .5;
  double p_10 = .5;
  double p_11 = .5;
  double probs[num_seq];
  double total_prob = 0.0;

  for (byte b = 0; b <= 15; b++) {
    if (!byte_to_bits(1, &b, NBITSINBYTE, 8, seq)) {
      printf("bad conversion\n");
      return false;
    }
    probs[(int) b] = byte_markov_sequence_probability(seq_len, seq, p_0, p_1,
        p_00, p_01, p_10, p_11);
  }

  total_prob = 0.0;
  for (int i = 0; i < num_seq; i++)
    total_prob += probs[i];

  printf("\n");
  printf("P(0): %lf, p(1): %lf, P(0|0): %lf, P(1|0): %lf, P(1|0): %lf, P(1|1): %lf\n",
    p_0, p_1, p_00, p_01, p_10, p_11);
  printf("Total prob: %lf\n", total_prob);
  for(int i = 0; i < num_seq; i++) {
    printf("Prob(%x)= %lf ", i, probs[i]);
    if ((i%4) == 3)
      printf("\n");
  }

  p_00 = .75;
  p_01 = .25;
  p_10 = .25;
  p_11 = .75;
  for (byte b = 0; b <= 15; b++) {
    if (!byte_to_bits(1, &b, NBITSINBYTE, 8, seq)) {
      printf("bad conversion\n");
      return false;
    }
    probs[(int) b] = byte_markov_sequence_probability(seq_len, seq, p_0, p_1,
        p_00, p_01, p_10, p_11);
  }

  total_prob = 0.0;
  for (int i = 0; i < num_seq; i++)
    total_prob += probs[i];

  printf("\n");
  printf("P(0): %lf, p(1): %lf, P(0|0): %lf, P(1|0): %lf, P(1|0): %lf, P(1|1): %lf\n",
    p_0, p_1, p_00, p_01, p_10, p_11);
  printf("Total prob: %lf\n", total_prob);
  for(int i = 0; i < num_seq; i++) {
    printf("Prob(%x)= %lf ", i, probs[i]);
    if ((i%4) == 3)
      printf("\n");
  }
  return true;
}

bool test_entropy() {
  const int num_bits_to_test = 4096;
  byte one_bit_per_byte[num_bits_to_test];
  byte all_bits_in_byte[num_bits_to_test / NBITSINBYTE];

  memset(one_bit_per_byte, 0, num_bits_to_test);
  memset(all_bits_in_byte, 0, num_bits_to_test / NBITSINBYTE);

  printf("\n");
  print_bytes(num_bits_to_test / NBITSINBYTE, all_bits_in_byte);
  printf("\n");

  double s_ent = byte_shannon_entropy(255,
        num_bits_to_test / NBITSINBYTE, all_bits_in_byte);
  printf("Shannon entropy: %lf\n", s_ent);
  double min_ent = most_common_value_entropy(255, num_bits_to_test / NBITSINBYTE, all_bits_in_byte);
  printf("Min entropy: %lf\n", min_ent);
  double mark_ent = byte_markov_entropy(num_bits_to_test, one_bit_per_byte);
  printf("Markov entropy: %lf\n", mark_ent);
  printf("\n");

  crypto_get_random_bytes(num_bits_to_test / NBITSINBYTE, all_bits_in_byte);
  if (!bits_to_byte(num_bits_to_test / NBITSINBYTE, all_bits_in_byte, NBITSINBYTE,
                  num_bits_to_test, one_bit_per_byte)) {
    printf("bad conversion\n");
    return false;
  }

  printf("\n");
  print_bytes(num_bits_to_test / NBITSINBYTE, all_bits_in_byte);
  printf("\n");

  s_ent = byte_shannon_entropy(255, num_bits_to_test / NBITSINBYTE, all_bits_in_byte);
  printf("Shannon entropy: %lf\n", s_ent);
  min_ent = most_common_value_entropy(255, num_bits_to_test / NBITSINBYTE, all_bits_in_byte);
  printf("Min entropy: %lf\n", min_ent);
  mark_ent = byte_markov_entropy(num_bits_to_test, one_bit_per_byte);
  printf("Markov entropy: %lf\n", mark_ent);
  printf("\n");

  return true;
}

bool test_runs() {
  const int num_bits_to_test = 4096;
  byte one_bit_per_byte[num_bits_to_test];
  byte all_bits_in_byte[num_bits_to_test / NBITSINBYTE];

  memset(one_bit_per_byte, 0, num_bits_to_test);
  memset(all_bits_in_byte, 0, num_bits_to_test / NBITSINBYTE);

  crypto_get_random_bytes(num_bits_to_test / NBITSINBYTE, all_bits_in_byte);
  if (!byte_to_bits(num_bits_to_test / NBITSINBYTE, all_bits_in_byte, NBITSINBYTE,
                    num_bits_to_test, one_bit_per_byte)) {
    printf("bad conversion\n");
    return false;
  }

  printf("\n");
  print_bytes(num_bits_to_test / NBITSINBYTE, all_bits_in_byte);
  printf("\n");

  int num_runs = 0;
  double mu = 0.0;
  double sigma = 0.0;

  if (!runs_test(num_bits_to_test, one_bit_per_byte, &num_runs, &mu, &sigma)) {
    printf("runs test fails\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("Runs test, n: %d, num_runs: %d, mu: %lf, sigma: %lf\n",
           num_bits_to_test, num_runs, mu, sigma);
  }

  printf("\n");
  return true;
}

bool test_berlekamp_massey() {
  const int n = 128;
  byte bits[n];

  for (int i = 0; i < n; i++) {
    bits[i] = i % 4;
  }

  int sr_size = 0;
  if (!berlekamp_massy(n, bits, &sr_size)) {
    return false;
  }
  printf("Berlekamp massy, n: %d, sr size: %d\n", n, sr_size);
  return true;
}

bool test_excursion_test() {
  const int num_bytes_to_test = 1024;
  byte all_bits_in_byte[num_bytes_to_test];

  memset(all_bits_in_byte, 0, num_bytes_to_test);
  crypto_get_random_bytes(num_bytes_to_test, all_bits_in_byte);

  printf("\n");
  print_bytes(num_bytes_to_test, all_bits_in_byte);
  printf("\n");

  double largest_excursion = excursion_test(num_bytes_to_test, all_bits_in_byte);
  if (FLAGS_print_all) {
    printf("Excursion test, n: %d, maximum excursion: %06.2lf\n",
           num_bytes_to_test, largest_excursion);
  }
  printf("\n");
  return true;
}

bool test_periodicity_test() {
  const int n = 25;
  double data[n] = {
    0.0, 1.0, 2.0, 3.0, 4.0,
    0.0, 1.0, 2.0, 3.0, 4.0,
    0.0, 1.0, 2.0, 3.0, 4.0,
    0.0, 1.0, 2.0, 3.0, 4.0,
    0.0, 1.0, 2.0, 3.0, 4.0,
  };
  double transform[n];

  if (!real_dft(n, data, transform)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("\ndft\n");
    printf("data     :");
    for (int i = 0; i < n; i++)
      printf("%5.1lf", data[i]);
    printf("\n");
    printf("transform:");
    for (int i = 0; i < n; i++)
      printf("%5.1lf", transform[i]);
    printf("\n");
    printf("\n");
  }

  byte x[n] = {
    0, 1, 2, 3, 4,
    0, 1, 2, 3, 4,
    0, 1, 2, 3, 4,
    0, 1, 2, 3, 4,
    0, 1, 2, 3, 4,
  };
  int r = 0;
  int lag = 1;
  if (!periodicity_test(n, x, lag, &r)) {
    return false;
  }
  if (FLAGS_print_all) {
    print_bytes(n, x);
    printf("period test with lag %d: %d\n", lag, r);
  }
  lag = 5;
  if (!periodicity_test(n, x, lag, &r)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("period test with lag %d: %d\n", lag, r);
  }
  return true;
}

bool test_chi_squared_test() {
  const int num_bits_to_test = 4096;
  byte one_bit_per_byte[num_bits_to_test];
  byte all_bits_in_byte[num_bits_to_test / NBITSINBYTE];

  memset(one_bit_per_byte, 0, num_bits_to_test);
  memset(all_bits_in_byte, 0, num_bits_to_test / NBITSINBYTE);

  crypto_get_random_bytes(num_bits_to_test / NBITSINBYTE, all_bits_in_byte);
  if (!byte_to_bits(num_bits_to_test / NBITSINBYTE, all_bits_in_byte, NBITSINBYTE,
                    num_bits_to_test, one_bit_per_byte)) {
    printf("bad conversion\n");
    return false;
  }

  printf("\n");
  print_bytes(num_bits_to_test / NBITSINBYTE, all_bits_in_byte);
  printf("\n");

  double chi_value= 0.0;
  double p[2] = {0.5, 0.5};
  if (!chi_squared_test(num_bits_to_test, one_bit_per_byte, 2, p, &chi_value)) {
    printf("runs test fails\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("Chi squared test, n: %d, chi_squared: %lf\n",
           num_bits_to_test, chi_value);
  }

  printf("\n");
  return true;
}

bool test_compression_test() {
  const int n = 100;
  byte x[n];
  int compressed = 0;

  for (int j = 0; j < n; j++)
    x[j] = j % 4;

  if (!compression_test(n, x, &compressed)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("Compression test, uncompressed size: %d, compressed size: %d\n", n, compressed);
  }
  return true;
}

TEST (drng, test_ctr_drng) {
  EXPECT_TRUE(test_ctr_drng());
}
TEST (entropy_tests, test_entropy) {
  EXPECT_TRUE(test_entropy());
}
TEST (markov_tests, test_markov) {
  EXPECT_TRUE(test_markov());
}
TEST (stat_tests, test_stat) {
  EXPECT_TRUE(test_runs());
  EXPECT_TRUE(test_berlekamp_massey());
  EXPECT_TRUE(test_excursion_test());
  EXPECT_TRUE(test_periodicity_test());
  EXPECT_TRUE(test_chi_squared_test());
  EXPECT_TRUE(test_compression_test());
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
