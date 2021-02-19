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
// File: probability_support.h

#ifndef _PROBABILITY_SUPPORT_H_
#define _PROBABILITY_SUPPORT_H_
#include <crypto_support.h>
#include <unistd.h>
#include <stdio.h>
#include <math.h>

void print_hex_uint32_array(int n, uint32_t* data);
void print_uint32_array(int n, uint32_t* data);
bool collect_difference_samples(int num_samples, uint32_t* data,
            uint32_t interval, int num_bits, int divisor);
bool write_graph_data(string file_name, int nbins, uint32_t* bins);
double calculate_mean(int num_samples, uint32_t* data);
double calculate_variance(int num_samples, uint32_t* data, double mean);
bool bin_conditional_data(int num_samples, uint32_t* data, int nbins, uint32_t* bins, uint32_t base_bin);
bool bin_raw_data(int num_samples, uint32_t* data, int nbins, uint32_t* bins);
bool calculate_entropies(int num_samples, int nbins, uint32_t* bins, double* shannon_entropy,
  double* renyi_entropy, double* min_entropy);
bool write_data(string file_name, int num_samples, uint32_t* data);
bool read_data(string file_name, int* num_samples, uint32_t** data);

void zero_uint32_array(int l, uint32_t* n);
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

