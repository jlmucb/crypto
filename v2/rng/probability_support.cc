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
// File: probability_support.cc

#include <crypto_support.h>
#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include "probability_support.h"

void zero_uint32_array(int l, uint32_t* n) {
  for (int i = 0; i < l; i++) {
    n[i] = 0;
  }
}

void print_uint64(int n, uint64_t* x) {
  for (int i = 0; i < n; i++) {
    printf("%016lx ", x[i]);
  }
}

void print_hex_uint32_array(int n, uint32_t* data) {
  int i;
  for (i = 0; i < n; i++) {
    printf("%04x ", data[i]);
    if ((i%8) == 7)
      printf("\n");
  }
  if ((i%8) != 0)
     printf("\n");
}

void print_uint32_array(int n, uint32_t* data) {
  int i;
  for (i = 0; i < n; i++) {
    printf("%04d ", data[i]);
    if ((i%8) == 7)
      printf("\n");
  }
  if ((i%8) != 0)
     printf("\n");
}

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

bool collect_difference_samples(int num_samples, uint32_t* data,
            uint32_t interval, int num_bits, int divisor) {
  uint64_t mask = 0ULL;
  for (int i = 0; i < num_bits; i++) {
    mask = (mask << 1) | 1ULL;
  }

  uint64_t last = read_rdtsc();
  uint64_t current = 0ULL;
  uint64_t difference= 0ULL;

  for (int i = 0; i < num_samples; i++) {
    usleep((uint32_t)interval);
    current = read_rdtsc();
    difference = current - last;
    last = current;
    difference = (difference / ((uint64_t)divisor)) & mask;
    data[i] = (uint32_t) difference;
  }
  return true;
}

bool write_graph_data(string file_name, int nbins, uint32_t* bins) {
  int fd = creat(file_name.c_str(), S_IRWXU | S_IRWXG);
  if (fd < 0) {
    printf("Can't create %s\n", file_name.c_str());
    return false;
  }
  if (write(fd, (const void*)&nbins, (size_t)sizeof(int)) < 0)
    return false;
  if (write(fd, bins, (size_t)(nbins* (int)sizeof(uint32_t))) < 0)
    return false;
  close(fd);
  return true;
}

double calculate_mean(int num_samples, uint32_t* data) {
  uint64_t sum = 0ULL;

  for (int i = 0; i < num_samples; i++) {
    sum += (uint64_t) data[i];
  }
  double mean = ((double)sum) / ((double)num_samples);
  return mean;
}

double calculate_variance(int num_samples, uint32_t* data, double mean) {
  double var = 0.0;
  double sum = 0;
  double t = 0.0;

  for (int i = 0; i < num_samples; i++) {
    t = mean - (double)data[i];
    sum += t * t;
  }
  return sum / (((double) num_samples) - 1);
}

bool bin_conditional_data(int num_samples, uint32_t* data, int nbins, uint32_t* bins, uint32_t base_bin) {
  for(int i = 0; i < nbins; i++) {
    bins[i]= 0;
  }
  for (int i = 0; i < (num_samples - 1); i++) {
    if ((int)data[i] >= nbins)
      continue;
    if (data[i] != base_bin)
      continue;
    bins[data[i + 1]]++;
  }
  return true;
}

bool bin_raw_data(int num_samples, uint32_t* data, int nbins, uint32_t* bins) {
  for(int i = 0; i < nbins; i++) {
    bins[i]= 0;
  }
  for (int i = 0; i < num_samples; i++) {
    if ((int)data[i] >= nbins)
      continue;
    bins[data[i]]++;
  }
  return true;
}

bool calculate_entropies(int num_samples, int nbins, uint32_t* bins, double* shannon_entropy,
  double* renyi_entropy, double* min_entropy) {
  double shannon = 0.0;
  double renyi = 0.0;
  double max = 0.0;
  double p;
  for(int i = 0; i < nbins; i++) {
    if (bins[i] == 0)
      continue;
    p = ((double) bins[i]) / ((double) num_samples);
    shannon += p * log(p);
    renyi += p * p;
    if (p > max)
      max = p;
  }
  *shannon_entropy = - shannon / log(2.0);
  *renyi_entropy = -log(renyi) / log(2.0);
  *min_entropy = -log(max) / log(2.0);
  return max;
}

bool write_data(string file_name, int num_samples, uint32_t* data) {
  int fd = creat(file_name.c_str(), S_IRWXU | S_IRWXG);
  if (fd < 0) {
    printf("Can't create %s\n", file_name.c_str());
    return false;
  }
  if (write(fd, (const void*)&num_samples, (size_t)sizeof(int)) < 0)
    return false;
  if (write(fd, data, (size_t)(num_samples * (int)sizeof(uint32_t))) < 0)
    return false;
  close(fd);
  return true;
}

bool read_data(string file_name, int* num_samples, uint32_t** data) {
  int fd = open(file_name.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    printf("Can't file_name%s\n", file_name.c_str());
    return false;
  }
  if (((int)read(fd, num_samples, sizeof(int))) < ((int)sizeof(int)))
    return false;
  *data = new uint32_t[*num_samples];
  int n = (*num_samples) * (int)sizeof(uint32_t);
  if ((int)read(fd, *data, n) < n)
    return false;
  close(fd);
  return true;
}

// IID tests:
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

// Min Entropy tests
//    Most Common Value Estimate
//    Collision Estimate
//    Markov Estimate
//    Compression Estimate
//    t-Tuple Estimate
//    Longest Repeated Substring (LRS) Estimate
//    Multi Most Common in Window Prediction Estimate
//    Lag Prediction Estimate
//    MultiMMC Prediction Estimate
//    LZ78Y Prediction Estimate

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

  if (seq[0] == 0)
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

#if 1
  printf("P(0): %lf, P(1): %lf\n", p_0, p_1);
  printf("P(0|0): %lf, P(1|0): %lf, P(0|1): %lf, P(1|1): %lf\n", 
    p_00, p_01, p_10, p_11);
#endif

  const int seq_len = 16;
  byte seq[seq_len + 8];
  int num_seq = 1 << seq_len;
  double probs[num_seq];

  for (uint32_t b = 0; b < num_seq; b++) {
    if (!bits_to_byte(seq_len / NBITSINBYTE, (byte*)&b, seq_len, seq)) {
      printf("bad conversion\n");
      return -1;
    }
    probs[(int) b] = markov_sequence_probability(seq_len, seq, p_0, p_1,
        p_00, p_01, p_10, p_11);
  }

  int i_max = largest_value_index(num_seq, probs);
  if (i_max < 0)
    return 0.0;
  double p_max = probs[i_max];
  double min_e = -lg(p_max) / ((double) seq_len) ;
#if 1
  printf("p_max: %lf, min_e: %lf\n", p_max, min_e);
#endif
  if (min_e > 1.0)
    min_e = 1.0;
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

bool runs_test(int n, byte* s, int* number_of_runs, double* mu, double* sigma) {
  byte current_value = s[0];
  int current_run_length = 1;
  int num_runs = 1;
  int n0 = 0;
  int n1 = 0;

  if (current_value == 0)
    n0++;
  else
    n1++;

  for (int i = 1; i < n; i++) {
    if (current_value == 0)
      n0++;
    else
      n1++;
    if (current_value != s[i]) {
      num_runs++;
      current_run_length = 1;
      current_value = s[i];
    }
    current_run_length++;
  }
  *number_of_runs = num_runs;
  *mu = (2.0 * ((double) n1) * ((double) n0)) / ((double) n) + 1.0;
  *sigma = sqrt(((*mu - 1.0)*(*mu - 2.0)) / ((double) (n-1)));
  // n1 / n is normally distributed with mu and sigma parameters

  return true;
}

// copy a to b
void copy_byte_array(int n, byte* a, byte* b) {
  for (int i = 0; i < n; i++)
    b[i] = a[i];
}

// Determine c[0],...,c[n-1] that gives syndrones of s[n-1] + c[0]s[n-2] + ... + c[*L-1] s[n-*L]
// *L is the length of the shortest LFSR for s
bool berlekamp_massy(int n, byte* s, int* L) {
  byte b[n];
  byte c[n];
  byte t[n];

  b[0] = 1;
  c[0] = 1;
  for (int i = 1; i < n; i++) {
    b[i] = 0;
    c[i] = 0;
  }

  *L = 0;
  int m = -1;
  byte d = 0;
  for (int k = 0; k < n; k++) {
    for (int j = 1; j <= *L; j++) {
      d ^= c[j] * s[k-j];
    }
    d ^= s[k];
    if (d != 0) {
      copy_byte_array(n, c, t);
      // c[k-m] = c[k-m] ^ b[0], ... , b[n-k-1+m]^c[n-1]
      for (int j = (k-m); j < n; j++) {
        c[j] = c[j]^b[m-k+j];
      }
      if (*L < (n / 2)) {
        *L = k - 1 - *L;
        m = k;
        copy_byte_array(n, t, b);
      }
    }
  }

  return true;
}

double sum(int n, byte* x) {
  double total = 0.0;
  for (int i = 0; i < n; i++)
    total += (double)x[i];
  return total;
}

double average(int n, byte* x) {
  double total = sum(n, x);;
  return total / ((double) n);
}

// largest deviation from the average
double excursion_test(int n, byte* x) {
  double av = average(n, x);
  double largest_excursion = 0.0;
  double d;
  double t;
  double s;

  if (n <= 0)
    return 0.0;

  for (int i = 0; i < n; i++) {
    s = sum(i + 1, x);
    t = s - ((double)(i + 1)) * av;
    if (t < 0.0)
      t = -t;
    // printf("i: %d, n: %d, sum: %7.2lf, av: %7.2lf, t: %7.2lf\n", i, n, s, av, t);
    if (t > largest_excursion)
      largest_excursion = t;
  }

  return largest_excursion;
}

bool chi_squared_test(int n, byte* x, int num_values, double* p, double* chi_value) {
  int count[num_values];

  for (int i = 0; i < num_values; i++)
    count[i] = 0;
  for (int i = 0; i < n; i++) {
      count[(int)x[i]]++;
  }

  double chi_squared = 0.0;

  for (int i = 0; i < num_values; i++) {
      chi_squared += (((double)count[(int)x[i]]) - ((double)n) * p[i]) / (((double)n) * p[i]);
  }
  *chi_value = chi_squared;
  return true;
}

bool complex_fourier_sum(int n, int k, double* x, double* real, double* im) {
  double real_total = 0.0;
  double im_total = 0.0;
  double t;

  for (int j = 0; j < n; j++) {
    t = -(2.0 * pi * ((double)j) * ((double)k)) / ((double)n);
    real_total += x[j] * cos(t);
    im_total += x[j] * sin(t);
  }
  *real = real_total;
  *im= im_total;
  return true;
}

// X[k] = sum from j = 0 to j= n-1  x[j] e^(-2 pi i)jk/n
// We return amplitude coefficients
bool real_dft(int n, double* data, double* transform) {
  double real_value = 0.0;
  double im_value = 0.0;

  for (int k = 0; k < n; k++) {
    if (!complex_fourier_sum(n, k, data, &real_value, &im_value)) {
      return false;
    }
#if 0
    printf("X[%d] = %7.2lf + i %7.2lf\n", k, real_value, im_value);
#endif
    transform[k] = sqrt(real_value * real_value + im_value * im_value);
  }
  return true;
}

// The periodicity test determines the number of periodic structures in the data.
// The test takes a lag parameter p as input, where p < L, T is calculated as follows:
//    1. Initialize T to zero.
//    2. For i = 1 to L − p
//    If (s i = s i+p ), increment T by one.
bool periodicity_test(int n, byte* s, int lag, int* result) {
  int coincident = 0;
  for (int i = 0; i < (n-lag); i++) {
    if (s[i] == s[i + lag])
      coincident++;
  }
  *result = coincident;
  return true;
}

/*
 *  LZ77 compression
 *    while input is not empty do
 *        prefix := longest prefix of input that begins in window
 *        if prefix exists then
 *            i := distance to start of prefix
 *           l := length of prefix
 *           c := char following prefix in input
 *       else
 *            i := 0
 *            l := 0
 *            c := first char of input
 *        end if
 *        output (i, l, c)
 *        s := pop l + 1 chars from front of input
 *        discard l + 1 chars from front of window
 *        append s to back of window
 *    repeat
 */
extern uint32_t lz77_compress (uint8_t *uncompressed_text, uint32_t uncompressed_size,
         uint8_t *compressed_text);
bool compression_test(int n, byte* s, int* compressed) {
  byte compressed_bytes[n];
  *compressed = lz77_compress (s, n, compressed_bytes);
  return true;
}