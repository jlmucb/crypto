//
// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: drng.h

#ifndef _CRYPTO_DRNG_H__
#define _CRYPTO_DRNG_H__
#include "crypto_support.h"
#include "sha256.h"


class hash_drng {
  enum {MAXPOOL_SIZE = 4096};
public:
  bool initialized_;
  int reseed_ctr_;
  int reseed_interval_;
  int num_entropy_bits_present_;
  int num_ent_bits_required_;
  int current_entropy_in_pool_;
  int current_size_pool_;
  int pool_size_;
  int hash_byte_output_size_;
  int seed_len_bits_;
  int seed_len_bytes_;
  byte pool_[MAXPOOL_SIZE];
  byte C_[64];
  byte V_[64];

  sha256 hash_obj_;

  hash_drng();
  ~hash_drng();

  int entropy_estimate();
  void set_policy(int n_ent, int byte_pool_size, int reseed_interval);
  void add_entropy(int size_bytes, byte* bits, int ent);
  bool health_check();
  void hash(int byte_size_in, byte* in, byte* out);
  void hash_df(int byte_size_in, byte* in, int bit_size_out, byte* out);
  void hash_gen(int num_requested_bits, byte* out);
  bool init(int size_nonce, byte* nonce, int size_personalization,
            byte* personalization);
  bool reseed();
  bool generate(int num_bits_needed, byte* out, int n_add_in_bits,
            byte* add_in_bits);
};

#if 0
double lg(double x);
bool bits_to_byte(int n_bit_bytes, byte* all_bits_in_byte,
                  int n_one_bit_per_byte, byte* one_bit_per_byte);
bool byte_to_bits(int n_one_bit_per_byte, byte* one_bit_per_byte,
                  int n_bit_bytes, byte* all_bits_in_byte);
double most_common_value_entropy(int largest_possible_sample,
          int num_samples, byte* samples);
double markov_sequence_probability(int seq_len, byte* seq,
  double p_0, double p_1, double p_00, double p_01, double p_10, double p_11);
double markov_entropy(int num_samples, byte* samples);
double shannon_entropy(int largest_possible_sample,
        int num_samples, byte* samples);
bool real_dft(int n, double* data, double* transform);
bool runs_test(int n, byte* s, int* number_of_runs, double* mu, double* sigma);
bool berlekamp_massy(int n, byte* s, int* L);
double excursion_test(int n, byte* s);
bool chi_squared_test(int n, byte* x, int num_values, double* p, double* chi_value);
bool periodicity_test(int n, byte* s, int lag, int* result);
bool compression_test(int n, byte* s, int* compressed);
#endif
#endif


