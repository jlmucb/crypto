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

const double pi = 3.141592653589793;
const double e = 2.718281828459054;

double lg(double x);

void zero_uint32_array(int l, uint32_t* n);
void zero_int16_array(int l, int16_t* n);
void zero_double_array(int l, double* n);
void zero_byte_array(int l, byte* n);
void zero_int_array(int l, int* n);

void print_hex_uint32_array(int n, uint32_t* data);
void print_uint32_array(int n, uint32_t* data);
void print_int16_array(int n, int16_t* data);
void print_double_array(int n, double* data);

bool collect_difference_samples(int num_samples, uint32_t* data,
            uint32_t interval, int num_bits, int divisor);

int bin_population(int nbins, uint32_t* bins);
bool bin_conditional_data(int num_samples, uint32_t* data, int nbins, uint32_t* bins, uint32_t base_bin);
bool bin_raw_data(int num_samples, uint32_t* data, int nbins, uint32_t* bins);
bool bin_raw_byte_data(int num_samples, byte* data, int nbins, byte* bins);
bool bin_int16_data(int num_samples, int16_t* data, int nbins, uint32_t* bins);

bool write_data(string file_name, int num_samples, uint32_t* data);
bool read_data(string file_name, int* num_samples, uint32_t** data);

bool uint32_to_bytes(int n, uint32_t* in, byte* out);

void print_bits(int n, byte* x);
bool byte_to_bits(int num_bytes, byte* in, int bits_per_byte,
                  int num_bits, byte* out);
bool bits_to_byte(int num_bits, byte* in, int bits_per_byte,
             int num_bytes, byte* out);

double expected_value(int n, double* p, double* x);
double variance(int n, double mean, double* p, double* x);
double shannon_entropy(int n, double* p);
double renyi_entropy(int n, double* p);
double min_entropy(int n, double* p);
int non_binary_random(uint32_t n);

inline int index(int n, int m, int i, int j) {
  return m * i + j;
}
bool calculate_marginal_probability(int n, int m, int var_num, double* p_xy, double* p);
double covariance(int n, int m, double mean_x, double* x,
                 double mean_y, double* y, double* p_xy);
double correlate(int n, int m, double mean_x, double sigma_x, double* x,
                 double mean_y, double sigma_y, double* y, double* p_xy);

bool write_graph_data(string file_name, int nbins, uint32_t* bins);
bool write_general_graph_data(string file_name, int n, double* x, double* y);

double factorial(int n);
double choose(int n, int k);
byte most_common_byte(int num_samples, byte* values);

bool binomial_test(int num_samples, byte* values,
      byte success_value, double p, double alpha, double* residual);

double calculate_uint32_mean(int num_samples, uint32_t* data);
double calculate_uint32_variance(int num_samples, uint32_t* data, double mean);
double calculate_int16_mean(int num_samples, int16_t* data);
double calculate_int16_variance(int num_samples, int16_t* data, double mean);
bool calculate_second_differences(int num_samples, uint32_t* old_data, int16_t* new_data);

bool calculate_bin_entropies(int num_samples, int nbins, uint32_t* bins, double* shannon_entropy,
  double* renyi_entropy, double* min_entropy);

double most_common_value_entropy(int largest_possible_sample,
          int num_samples, byte* samples);
double byte_markov_sequence_probability(int seq_len, byte* seq,
  double p_0, double p_1, double p_00, double p_01, double p_10, double p_11);
double byte_markov_entropy(int num_samples, byte* samples);
double byte_shannon_entropy(int largest_possible_sample,
        int num_samples, byte* samples);

bool real_dft(int n, double* data, double* transform);
bool runs_test(int n, byte* s, int* number_of_runs, double* mu, double* sigma);
bool berlekamp_massy(int n, byte* s, int* L);
double excursion_test(int n, byte* s);
bool chi_squared_test(int n, byte* x, int num_values, double* p, double* chi_value);
bool periodicity_test(int n, byte* s, int lag, int* result);
bool compression_test(int n, byte* s, int* compressed);

double chi_critical_upper(int v, double confidence);
double chi_critical_lower(int v, double confidence);
#endif

