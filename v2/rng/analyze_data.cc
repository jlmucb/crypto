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
// File: analyze_data.cc

#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "entropy_collection.h"
#include "probability_support.h"
#include "aes.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");
DEFINE_string(data_file_name, "data.txt", "Data file name");



bool read_data_file() {
  file_util data_file;

  // int read_file(const char* filename, int size, byte* buf);

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


int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  init_crypto();

  // Read data
  file_util f;
  if (!f.open(FLAGS_data_file_name.c_str())) {
    printf("Can't open %s\n", FLAGS_data_file_name.c_str());
    return 1;
  }
  int sz = f.bytes_in_file();
  f.close();
  char txt_data[sz + 1];

  // Run tests

  close_crypto();
  printf("\n");
  return 0;
}
