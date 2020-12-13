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
// File: min_entropy.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <math.h>
#include <crypto_support.h>
#include <drng.h>

// Entropy tests:
//    Adaptive proportion test
//    Permutation test
//    Length of directional runs
//    # increases/decreases
//    # runs based on median
//    Length of runs based on median
//    Excursion
//    Average collisions test
//    Max collision
//    Periodicity
//    Covariance
//    Compression
//    Chi


// s_0, s_1, ..., s_(L-1)  are samples from A= <x_0,..., x_(k-1)>
//
// Most common value: p_m = max_i {#x_i in S)/ |S|
//    p_u = min(1, p_m + 2.576sqrt([p_m(1-p_m)/(L-1)]
//    min_e = -lg(p_u)
//
// Markov
//    P_0 = #(0 in S)/L, P_1 = 1- P_0
//    P_00 = #(00 in S) / (#(00 in S) - #(01 in S))
//    P_01 = #(00 in S) / (#(00 in S) - #(01 in S))
//    P_10 = #(10 in S) / (#(10 in S) - #(11 in S))
//    P_11 = #(01 in S) / (#(11 in S) - #(11 in S))
//
//  Find p_max = most likely 128 bit sequence
//    min_e = min(-lg(p_max), 1)

double lg(double x) {
  return log(x) / log (2.0);
}

bool bits_to_byte(int n_bit_bytes, byte* all_bits_in_byte,
                  int n_one_bit_per_byte, byte* one_bit_per_byte) {
  if ((NBITSINBYTE * n_bit_bytes) > n_one_bit_per_byte)
    return false;
  byte b;
  for (int i = 0; i < n_bit_bytes; i++) {
    b = all_bits_in_byte[i];
    for (int j = 0; j < NBITSINBYTE; j++) {
      one_bit_per_byte[NBITSINBYTE * i + j] = b & 0x1;
      b >>= 1;
    }
  }
  return true;
}

bool byte_to_bits(int n_one_bit_per_byte, byte* one_bit_per_byte,
                  int n_bit_bytes, byte* all_bits_in_byte) {
  if (((n_one_bit_per_byte + NBITSINBYTE - 1) / NBITSINBYTE) > n_one_bit_per_byte)
    return false;
  byte b;
  for (int i = 0; i < n_one_bit_per_byte; i+= NBITSINBYTE) {
    b = 0;
    for (int j = 0; j < NBITSINBYTE; j++) {
      b <<= 1;
      b |= one_bit_per_byte[NBITSINBYTE * i + j];
    }
    all_bits_in_byte[i / NBITSINBYTE] = b;
  }
  return true;
}

int largest_value_index(int n, double* v) {
  int m = 0;
  double largest = v[0];

  for (int i = 1; i < n; i++) {
    if (v[i] > largest)
      m = i;
  }
  return m;
}

// samples are  integers 0, 1, ..., largest_possible_sample
double most_common_value_entropy(int largest_possible_sample, int num_samples, byte* samples) {
  int sample_index = largest_possible_sample + 1;
  double v[sample_index];
  for (int i = 0; i < sample_index; i++)
    v[i] = 0.0;

  for( int i = 0; i < num_samples; i++) {
    v[(int)samples[i]] += 1.0;
  }
  for( int i = 0; i < sample_index; i++) {
    v[i] /= ((double) num_samples);
  }

  int n = largest_value_index(sample_index, v);
  double p_u = v[n] + 2.576 * sqrt((v[n] * (1 - v[n])) / ((double) (num_samples - 1)));
  if (1.0 < p_u)
    p_u = 1.0;
  if (p_u == 0.0)
    return 0.0;
  return -lg(p_u);
}

double markov_sequence_probability(int seq_len, byte* seq,
  double p_0, double p_1,
  double p_00, double p_01, double p_10, double p_11) {

  double p = 0.0;

  if (seq[0] = 0)
    p = p_0;
  else
    p = p_1;

  for (int i = 1; i < seq_len; i++) {
    if (seq[i-1] == 0 && seq[i] == 0) {
      p *= p_00;
    } else if (seq[i-1] == 0 && seq[i] == 1) {
      p *= p_01;
    } else if (seq[i-1] == 1 && seq[i] == 0) {
      p *= p_10;
    } else {
      p *= p_11;
    }
  }
  return p;
}

// samples are bytes containing 1 bit
double markov_entropy(int num_samples, byte* samples) {
  int n_zero = 0;
  int n_one= 0;
  int n_00 = 0;
  int n_01 = 0;
  int n_10 = 0;
  int n_11 = 0;

  for (int i = 0; i < (num_samples - 1); i++) {
    if (samples[i] == 0)
      n_zero++;
    else
      n_one++;
    if (samples[i] == 0 && samples[i + 1] == 0) {
      n_00++;
    } else if (samples[i] == 0 && samples[i + 1] == 1) {
      n_01++;
    } else if (samples[i] == 1 && samples[i + 1] == 0) {
      n_10++;
    } else {
      n_11++;
    }
  }

  double p_0 = ((double)n_zero) / ((double) num_samples);
  double p_1 = 1.0 - p_0;

  double p_00;
  double p_01;
  double p_10;
  double p_11;

  if ((n_00 + n_01) > 0) {
    p_00 = ((double) n_00) / ((double)(n_00 + n_01));
    p_01 = ((double) n_01) / ((double)(n_00 + n_01));
  } else {
    p_00 = 0.0;
    p_01 = 0.0;
  }
  if ((n_10 + n_11) > 0) {
    p_10 = ((double) n_10) / ((double)(n_10 + n_11));
    p_11 = ((double) n_11) / ((double)(n_10 + n_11));
  } else {
    p_10 = 0.0;
    p_11 = 0.0;
  }

#if 0
  printf("P(0): %lf, P(1): %lf\n", p_0, p_1);
  printf("P(0|0): %lf, P(1|0): %lf, P(0|1): %lf, P(1|1): %lf\n", 
    p_00, p_01, p_10, p_11);
#endif

  // largest probability of 128 bit sequence
  double p_max = 1.0;
  double min_e = -lg(p_max /128.0);
  if (min_e > 1.0)
    min_e =1.0;
  return min_e;
}

// samples are  integers 0, 1, ..., largest_possible_sample
double shannon_entropy(int largest_possible_sample, int num_samples, byte* samples) {
  int sample_index = largest_possible_sample + 1;
  double v[sample_index];
  for (int i = 0; i < sample_index; i++)
    v[i] = 0.0;

  for( int i = 0; i < num_samples; i++) {
    v[(int)samples[i]] += 1.0;
  }
  for( int i = 0; i < sample_index; i++) {
    v[i] /= ((double) num_samples);
  }

  double entropy = 0.0;
  for( int i = 0; i < sample_index; i++) {
    if (v[i] != 0.0)
      entropy += -v[i] * lg(v[i]);
  }
  return entropy;
}
