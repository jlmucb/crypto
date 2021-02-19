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
// File: entropy_support.h

#ifndef _ENTROPY_SUPPORT_H_
#define _ENTROPY_SUPPORT_H_
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
#endif

