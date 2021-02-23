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

void zero_int16_array(int l, int16_t* n) {
  for (int i = 0; i < l; i++) {
    n[i] = 0;
  }
}

void zero_double_array(int l, double* n) {
  for (int i = 0; i < l; i++) {
    n[i] = 0.0;
  }
}

void zero_byte_array(int l, byte* n) {
  for (int i = 0; i < l; i++) {
    n[i] = 0;
  }
}

void print_uint64_array(int n, uint64_t* x) {
  int i;

  for (i = 0; i < n; i++) {
    printf("%016lx ", x[i]);
    if ((i%4) == 3)
      printf("\n");
  }
  if ((i%4) == 3)
  printf("\n");
}

void print_int16_array(int n, int16_t* x) {
  int i;

  for (i = 0; i < n; i++) {
    printf("%03d ", x[i]);
    if ((i%8) == 7)
      printf("\n");
  }
  if ((i%8) != 0)
     printf("\n");
}

void print_double_array(int n, double* data) {
  int i;

  for (i = 0; i < n; i++) {
    printf("%8.4lf ", data[i]);
    if ((i%8) == 7)
      printf("\n");
  }
  if ((i%8) != 0)
     printf("\n");
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

bool uint32_to_bytes(int n, uint32_t* in, byte* out) {
  for (int i = 0; i < n; i++) {
    out[i] = (byte) (in[i] & 0xff);
  }
  return true;
}

bool write_data(string file_name, int num_samples, uint32_t* data) {
  int fd = open(file_name.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd < 0) {
    printf("Can't create %s\n", file_name.c_str());
    return false;
  }
  if (write(fd, (const void*)&num_samples, (int)sizeof(int)) <= 0) {
    printf("Can't write size in write_data\n");
    return false;
  }
  int n = num_samples * ((int)sizeof(uint32_t));
  if (write(fd, (const void*)data, n) <= 0) {
    printf("Can't write data in write_data\n");
    return false;
  }
  close(fd);
  return true;
}

bool read_data(string file_name, int* num_samples, uint32_t** data) {
  int fd = open(file_name.c_str(), O_RDONLY, 0644);
  if (fd < 0) {
    printf("Can't open file_name %s\n", file_name.c_str());
    return false;
  }
  if ((read(fd, (void*)num_samples, sizeof(int))) <= 0) {
    printf("Can't read size\n");
    return false;
  }
  *data = new uint32_t[*num_samples];
  if (*data == nullptr) {
    printf("data allocation fails\n");
    return false;
  }
  int n = (*num_samples) * (int)sizeof(uint32_t);
  if (read(fd, (void*)(*data), n) <= 0) {
    printf("Can't read data\n");
    return false;
  }
  close(fd);
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

int bin_population(int nbins, uint32_t* bins) {
  int total = 0;

  for (int i = 0; i < nbins; i++)
    total += bins[i];
  return total;
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

bool bin_signed_data(int num_samples, int16_t* data, int nbins, uint32_t* bins) {
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

double lg(double x) {
  return log(x) / log (2.0);
}

double expected_value(int n, double* p, double* x) {
  double sum = 0.0;

  for (int i = 0; i < n; i++) {
    sum += p[i] * x[i];
  }
  return sum;
}

double variance(int n, double mean, double* p, double* x) {
  double sum = 0.0;
  double t;

  for (int i = 0; i < n; i++) {
    t = x[i] - mean;
    sum += p[i] * t * t;
  }
  return sum;
}

bool calculate_marginal_probability(int n, int m, int var_num, double* p_xy, double* p) {
  // First var
  //    p[i] = sum_j^m p_xy[index(n,m,i,j)], i = 0, 1, ..., n - 1
  // Second var
  //    p[i] = sum_j^n p_xy[index(n,m,j,i)], i = 0, 1, ..., m - 1

  double sum;
  if (var_num == 0) {
    for (int i = 0; i < n; i++) {
      sum = 0.0;
      for (int j = 0; j < m; j++) {
        sum += p_xy[index(n, m, i, j)];
      }
      p[i] = sum;
    }
  } else {
    for (int i = 0; i < m; i++) {
      sum = 0.0;
      for (int j = 0; j < n; j++) {
        sum += p_xy[index(n, m, j, i)];
      }
      p[i] = sum;
    }
  }
  return true;
}

double covariance(int n, int m, double mean_x, double* x, double mean_y, double* y, double* p_xy) {
  double sum = 0.0;
  double t1, t2;

  for (int i = 0; i < n; i++) {
    t1 = x[i] - mean_x;
    for (int j = 0; j < m; j++) {
      t2 = y[i] - mean_y;
      sum += p_xy[index(n, m, i, j)] * t1 * t2;
    }
  }
  return sum;
}

double correlate(int n, int m, double mean_x, double sigma_x, double* x, double mean_y, double sigma_y, double* y, double* p_xy) {
  return covariance(n, m, mean_x, x, mean_y, y, p_xy) / (sigma_x * sigma_y);
}

double shannon_entropy(int n, double* p) {
  double sum = 0.0;

  for (int i = 0; i < n; i++) {
    if (p[i] > 0.0)
      sum += -p[i] * lg(p[i]);
  }
  return sum;
}

double renyi_entropy(int n, double* p) {
  double sum = 0.0;

  for (int i = 0; i < n; i++) {
    sum += p[i] * p[i];
  }
  return -lg(sum);
}

double min_entropy(int n, double* p) {
  double max = 0.0;

  for (int i = 0; i < n; i++) {
    if (p[i] > max)
      max = p[i];
  }
  if (max <= 0.0)
    return 0.0;
  return -lg(max);
}

void print_bits(int n, byte* x) {
  int i;

  for (i = 0; i < n; i++) {
    printf("%1x", x[i]);
    if ((i%8) == 7)
      printf(" ");
    if ((i%64) == 63)
      printf("\n");
  }
  if ((i%64) != 0)
     printf("\n");
}

bool bits_to_byte(int num_bits, byte* in,
                  int num_bytes, byte* out) {
  if (num_bytes < ((num_bits + NBITSINBYTE - 1) / NBITSINBYTE))
    return false;

  byte b;
  for (int i = 0; i < num_bits; i += NBITSINBYTE) {
    b = 0;
    for (int j = (NBITSINBYTE - 1); j >= 0; j--) {
      b = (b << 1) | in[i + j];
    }
    out[i / NBITSINBYTE] = b;
  }
  return true;
}

// take array of bytes and turn it into an array of one bit/byte
bool byte_to_bits(int num_bytes, byte* in,
                  int num_bits, byte* out) {
  if (num_bits < ((num_bytes + NBITSINBYTE - 1) / NBITSINBYTE) * NBITSINBYTE)
    return false;

  byte b;
  for (int i = 0; i < num_bytes; i++) {
    b = in[i];
    for (int j = 0; j < NBITSINBYTE; j++) {
      out[NBITSINBYTE * i + j] = (b & 0x01);
      b =  (b >> 1);
    }
  }
  return true;
}

//  File format:
//    num_bins (int)
//    num_bins uint32_t values consisting of the size of the bin
bool write_graph_data(string file_name, int nbins, uint32_t* bins) {
  int fd = open(file_name.c_str(), O_WRONLY  | O_CREAT | O_TRUNC,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
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

//  File format:
//    num_points (int)
//    num_points pair of doubles consisting of x and y coordinates
bool write_general_graph_data(string file_name, int n, double* x, double* y) {
  int fd = open(file_name.c_str(), O_WRONLY  | O_CREAT | O_TRUNC,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd < 0) {
    printf("Can't create %s\n", file_name.c_str());
    return false;
  }
  if (write(fd, (const void*)&n, (size_t)sizeof(int)) < 0)
    return false;
  for (int i = 0; i < n; i++) {
    if (write(fd, (const void*)&x[i], (size_t)(sizeof(double))) < 0)
      return false;
    if (write(fd, (const void*)&y[i], (size_t)(sizeof(double))) < 0)
      return false;
  }
  close(fd);
  return true;
}

bool calculate_second_differences(int num_samples, uint32_t* old_data, int16_t* new_data) {
  int16_t last = (int32_t)old_data[0];

  for (int i = 1; i < num_samples; i++) {
    new_data[i - 1] = ((int16_t)old_data[i]) - last;
    last = ((int16_t)old_data[i]);
  }
  return true;
}

double calculate_uint32_mean(int num_samples, uint32_t* data) {
  uint64_t sum = 0ULL;

  for (int i = 0; i < num_samples; i++) {
    sum += (uint64_t) data[i];
  }
  double mean = ((double)sum) / ((double)num_samples);
  return mean;
}

double calculate_uint32_variance(int num_samples, uint32_t* data, double mean) {
  double var = 0.0;
  double sum = 0;
  double t = 0.0;

  for (int i = 0; i < num_samples; i++) {
    t = mean - (double)data[i];
    sum += t * t;
  }
  return sum / (((double) num_samples) - 1);
}

double calculate_int32_mean(int num_samples, int16_t* data) {
  uint64_t sum = 0ULL;

  for (int i = 0; i < num_samples; i++) {
    sum += (uint64_t) data[i];
  }
  double mean = ((double)sum) / ((double)num_samples);
  return mean;
}

double calculate_int32_variance(int num_samples, int16_t* data, double mean) {
  double var = 0.0;
  double sum = 0;
  double t = 0.0;

  for (int i = 0; i < num_samples; i++) {
    t = mean - ((double)data[i]);
    sum += t * t;
  }
  return sum / (((double) num_samples) - 1);
}

bool calculate_bin_entropies(int num_samples, int nbins, uint32_t* bins, double* shannon_entropy,
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

double byte_markov_sequence_probability(int seq_len, byte* seq,
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
double byte_markov_entropy(int num_samples, byte* samples) {
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

  const int seq_len = 16;
  byte seq[seq_len + 8];
  int num_seq = 1 << seq_len;
  double probs[num_seq];

  for (uint32_t b = 0; b < num_seq; b++) {
    if (!byte_to_bits(seq_len / NBITSINBYTE, (byte*)&b, seq_len, seq)) {
      printf("bad conversion\n");
      return -1;
    }
    probs[(int) b] = byte_markov_sequence_probability(seq_len, seq, p_0, p_1,
        p_00, p_01, p_10, p_11);
  }

  int i_max = largest_value_index(num_seq, probs);
  if (i_max < 0)
    return 0.0;
  double p_max = probs[i_max];
  double min_e = -lg(p_max) / ((double) seq_len) ;
#if 0
  printf("p_max: %lf, min_e: %lf\n", p_max, min_e);
#endif
  if (min_e > 1.0)
    min_e = 1.0;
  return min_e;
}

// samples are  integers 0, 1, ..., largest_possible_sample
double byte_shannon_entropy(int largest_possible_sample, int num_samples, byte* samples) {
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
    t = fabs(s - (((double)(i + 1)) * av));
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
  double x_n = (double)n;
  double t;
  for (int i = 0; i < num_values; i++) {
    t = ((double)count[(int)x[i]]) - (x_n * p[i]);
    chi_squared += (t * t) / (x_n * p[i]);
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
  byte compressed_bytes[2 * n];
  *compressed = lz77_compress (s, n, compressed_bytes);
  return true;
}

// Chi squared critical values

const int num_levels = 5;
const double u_levels[num_levels] = {
  0.90, 0.95, 0.975, 0.99, 0.999,
};
const double l_levels[num_levels] = {
  0.10, 0.05, 0.025, 0.01, 0.001,
};

// Upper-tail critical values of chi-square distribution with ν degrees of freedom
const double upper_table[num_levels * 100] = {
  2.706,   3.841,   5.024,   6.635,  10.828,
  4.605,   5.991,   7.378,   9.210,  13.816,
  6.251,   7.815,   9.348,  11.345,  16.266,
  7.779,   9.488,  11.143,  13.277,  18.467,
  9.236,  11.070,  12.833,  15.086,  20.515,
  10.645,  12.592,  14.449,  16.812,  22.458,
  12.017,  14.067,  16.013,  18.475,  24.322,
  13.362,  15.507,  17.535,  20.090,  26.125,
  14.684,  16.919,  19.023,  21.666,  27.877,
  15.987,  18.307,  20.483,  23.209,  29.588,
  17.275,  19.675,  21.920,  24.725,  31.264,
  18.549,  21.026,  23.337,  26.217,  32.910,
  19.812,  22.362,  24.736,  27.688,  34.528,
  21.064,  23.685,  26.119,  29.141,  36.123,
  22.307,  24.996,  27.488,  30.578,  37.697,
  23.542,  26.296,  28.845,  32.000,  39.252,
  24.769,  27.587,  30.191,  33.409,  40.790,
  25.989,  28.869,  31.526,  34.805,  42.312,
  27.204,  30.144,  32.852,  36.191,  43.820,
  28.412,  31.410,  34.170,  37.566,  45.315,
  29.615,  32.671,  35.479,  38.932,  46.797,
  30.813,  33.924,  36.781,  40.289,  48.268,
  32.007,  35.172,  38.076,  41.638,  49.728,
  33.196,  36.415,  39.364,  42.980,  51.179,
  34.382,  37.652,  40.646,  44.314,  52.620,
  35.563,  38.885,  41.923,  45.642,  54.052,
  36.741,  40.113,  43.195,  46.963,  55.476,
  37.916,  41.337,  44.461,  48.278,  56.892,
  39.087,  42.557,  45.722,  49.588,  58.301,
  40.256,  43.773,  46.979,  50.892,  59.703,
  41.422,  44.985,  48.232,  52.191,  61.098,
  42.585,  46.194,  49.480,  53.486,  62.487,
  43.745,  47.400,  50.725,  54.776,  63.870,
  44.903,  48.602,  51.966,  56.061,  65.247,
  46.059,  49.802,  53.203,  57.342,  66.619,
  47.212,  50.998,  54.437,  58.619,  67.985,
  48.363,  52.192,  55.668,  59.893,  69.347,
  49.513,  53.384,  56.896,  61.162,  70.703,
  50.660,  54.572,  58.120,  62.428,  72.055,
  51.805,  55.758,  59.342,  63.691,  73.402,
  52.949,  56.942,  60.561,  64.950,  74.745,
  54.090,  58.124,  61.777,  66.206,  76.084,
  55.230,  59.304,  62.990,  67.459,  77.419,
  56.369,  60.481,  64.201,  68.710,  78.750,
  57.505,  61.656,  65.410,  69.957,  80.077,
  58.641,  62.830,  66.617,  71.201,  81.400,
  59.774,  64.001,  67.821,  72.443,  82.720,
  60.907,  65.171,  69.023,  73.683,  84.037,
  62.038,  66.339,  70.222,  74.919,  85.351,
  63.167,  67.505,  71.420,  76.154,  86.661,
  64.295,  68.669,  72.616,  77.386,  87.968,
  65.422,  69.832,  73.810,  78.616,  89.272,
  66.548,  70.993,  75.002,  79.843,  90.573,
  67.673,  72.153,  76.192,  81.069,  91.872,
  68.796,  73.311,  77.380,  82.292,  93.168,
  69.919,  74.468,  78.567,  83.513,  94.461,
  71.040,  75.624,  79.752,  84.733,  95.751,
  72.160,  76.778,  80.936,  85.950,  97.039,
  73.279,  77.931,  82.117,  87.166,  98.324,
  74.397,  79.082,  83.298,  88.379,  99.607,
  75.514,  80.232,  84.476,  89.591, 100.888,
  76.630,  81.381,  85.654,  90.802, 102.166,
  77.745,  82.529,  86.830,  92.010, 103.442,
  78.860,  83.675,  88.004,  93.217, 104.716,
  79.973,  84.821,  89.177,  94.422, 105.988,
  81.085,  85.965,  90.349,  95.626, 107.258,
  82.197,  87.108,  91.519,  96.828, 108.526,
  83.308,  88.250,  92.689,  98.028, 109.791,
  84.418,  89.391,  93.856,  99.228, 111.055,
  85.527,  90.531,  95.023, 100.425, 112.317,
  86.635,  91.670,  96.189, 101.621, 113.577,
  87.743,  92.808,  97.353, 102.816, 114.835,
  88.850,  93.945,  98.516, 104.010, 116.092,
  89.956,  95.081,  99.678, 105.202, 117.346,
  91.061,  96.217, 100.839, 106.393, 118.599,
  92.166,  97.351, 101.999, 107.583, 119.850,
  93.270,  98.484, 103.158, 108.771, 121.100,
  94.374,  99.617, 104.316, 109.958, 122.348,
  95.476, 100.749, 105.473, 111.144, 123.594,
  96.578, 101.879, 106.629, 112.329, 124.839,
  97.680, 103.010, 107.783, 113.512, 126.083,
  98.780, 104.139, 108.937, 114.695, 127.324,
  99.880, 105.267, 110.090, 115.876, 128.565,
 100.980, 106.395, 111.242, 117.057, 129.804,
 102.079, 107.522, 112.393, 118.236, 131.041,
 103.177, 108.648, 113.544, 119.414, 132.277,
 104.275, 109.773, 114.693, 120.591, 133.512,
 105.372, 110.898, 115.841, 121.767, 134.746,
 106.469, 112.022, 116.989, 122.942, 135.978,
 107.565, 113.145, 118.136, 124.116, 137.208,
 108.661, 114.268, 119.282, 125.289, 138.438,
 109.756, 115.390, 120.427, 126.462, 139.666,
 110.850, 116.511, 121.571, 127.633, 140.893,
 111.944, 117.632, 122.715, 128.803, 142.119,
 113.038, 118.752, 123.858, 129.973, 143.344,
 114.131, 119.871, 125.000, 131.141, 144.567,
 115.223, 120.990, 126.141, 132.309, 145.789,
 116.315, 122.108, 127.282, 133.476, 147.010,
 117.407, 123.225, 128.422, 134.642, 148.230,
 118.498, 124.342, 129.561, 135.807, 149.449,
};


// lower-tail critical values of chi-square distribution with ν degrees of freedom
const double lower_table[num_levels * 100] = {
  .016, .004, .001, .000, .000,
  .211, .103, .051, .020, .002,
  .584, .352, .216, .115, .024,
  1.064, .711, .484, .297, .091,
  1.610,  1.145, .831, .554, .210,
  2.204,  1.635,  1.237, .872, .381,
  2.833,  2.167,  1.690,  1.239, .598,
  3.490,  2.733,  2.180,  1.646, .857,
  4.168,  3.325,  2.700,  2.088,  1.152,
 4.865,  3.940,  3.247,  2.558,  1.479,
 5.578,  4.575,  3.816,  3.053,  1.834,
 6.304,  5.226,  4.404,  3.571,  2.214,
 7.042,  5.892,  5.009,  4.107,  2.617,
 7.790,  6.571,  5.629,  4.660,  3.041,
 8.547,  7.261,  6.262,  5.229,  3.483,
 9.312,  7.962,  6.908,  5.812,  3.942,
 10.085,  8.672,  7.564,  6.408,  4.416,
 10.865,  9.390,  8.231,  7.015,  4.905,
 11.651, 10.117,  8.907,  7.633,  5.407,
 12.443, 10.851,  9.591,  8.260,  5.921,
 13.240, 11.591, 10.283,  8.897,  6.447,
 14.041, 12.338, 10.982,  9.542,  6.983,
 14.848, 13.091, 11.689, 10.196,  7.529,
 15.659, 13.848, 12.401, 10.856,  8.085,
 16.473, 14.611, 13.120, 11.524,  8.649,
 17.292, 15.379, 13.844, 12.198,  9.222,
 18.114, 16.151, 14.573, 12.879,  9.803,
 18.939, 16.928, 15.308, 13.565, 10.391,
 19.768, 17.708, 16.047, 14.256, 10.986,
 20.599, 18.493, 16.791, 14.953, 11.588,
 21.434, 19.281, 17.539, 15.655, 12.196,
 22.271, 20.072, 18.291, 16.362, 12.811,
 23.110, 20.867, 19.047, 17.074, 13.431,
 23.952, 21.664, 19.806, 17.789, 14.057,
 24.797, 22.465, 20.569, 18.509, 14.688,
 25.643, 23.269, 21.336, 19.233, 15.324,
 26.492, 24.075, 22.106, 19.960, 15.965,
 27.343, 24.884, 22.878, 20.691, 16.611,
 28.196, 25.695, 23.654, 21.426, 17.262,
 29.051, 26.509, 24.433, 22.164, 17.916,
 29.907, 27.326, 25.215, 22.906, 18.575,
 30.765, 28.144, 25.999, 23.650, 19.239,
 31.625, 28.965, 26.785, 24.398, 19.906,
 32.487, 29.787, 27.575, 25.148, 20.576,
 33.350, 30.612, 28.366, 25.901, 21.251,
 34.215, 31.439, 29.160, 26.657, 21.929,
 35.081, 32.268, 29.956, 27.416, 22.610,
 35.949, 33.098, 30.755, 28.177, 23.295,
 36.818, 33.930, 31.555, 28.941, 23.983,
 37.689, 34.764, 32.357, 29.707, 24.674,
 38.560, 35.600, 33.162, 30.475, 25.368,
 39.433, 36.437, 33.968, 31.246, 26.065,
 40.308, 37.276, 34.776, 32.018, 26.765,
 41.183, 38.116, 35.586, 32.793, 27.468,
 42.060, 38.958, 36.398, 33.570, 28.173,
 42.937, 39.801, 37.212, 34.350, 28.881,
 43.816, 40.646, 38.027, 35.131, 29.592,
 44.696, 41.492, 38.844, 35.913, 30.305,
 45.577, 42.339, 39.662, 36.698, 31.020,
 46.459, 43.188, 40.482, 37.485, 31.738,
 47.342, 44.038, 41.303, 38.273, 32.459,
 48.226, 44.889, 42.126, 39.063, 33.181,
 49.111, 45.741, 42.950, 39.855, 33.906,
 49.996, 46.595, 43.776, 40.649, 34.633,
 50.883, 47.450, 44.603, 41.444, 35.362,
 51.770, 48.305, 45.431, 42.240, 36.093,
 52.659, 49.162, 46.261, 43.038, 36.826,
 53.548, 50.020, 47.092, 43.838, 37.561,
 54.438, 50.879, 47.924, 44.639, 38.298,
 55.329, 51.739, 48.758, 45.442, 39.036,
 56.221, 52.600, 49.592, 46.246, 39.777,
 57.113, 53.462, 50.428, 47.051, 40.519,
 58.006, 54.325, 51.265, 47.858, 41.264,
 58.900, 55.189, 52.103, 48.666, 42.010,
 59.795, 56.054, 52.942, 49.475, 42.757,
 60.690, 56.920, 53.782, 50.286, 43.507,
 61.586, 57.786, 54.623, 51.097, 44.258,
 62.483, 58.654, 55.466, 51.910, 45.010,
 63.380, 59.522, 56.309, 52.725, 45.764,
 64.278, 60.391, 57.153, 53.540, 46.520,
 65.176, 61.261, 57.998, 54.357, 47.277,
 66.076, 62.132, 58.845, 55.174, 48.036,
 66.976, 63.004, 59.692, 55.993, 48.796,
 67.876, 63.876, 60.540, 56.813, 49.557,
 68.777, 64.749, 61.389, 57.634, 50.320,
 69.679, 65.623, 62.239, 58.456, 51.085,
 70.581, 66.498, 63.089, 59.279, 51.850,
 71.484, 67.373, 63.941, 60.103, 52.617,
 72.387, 68.249, 64.793, 60.928, 53.386,
 73.291, 69.126, 65.647, 61.754, 54.155,
 74.196, 70.003, 66.501, 62.581, 54.926,
 75.100, 70.882, 67.356, 63.409, 55.698,
 76.006, 71.760, 68.211, 64.238, 56.472,
 76.912, 72.640, 69.068, 65.068, 57.246,
 77.818, 73.520, 69.925, 65.898, 58.022,
 78.725, 74.401, 70.783, 66.730, 58.799,
 79.633, 75.282, 71.642, 67.562, 59.577,
 80.541, 76.164, 72.501, 68.396, 60.356,
 81.449, 77.046, 73.361, 69.230, 61.137,
 82.358, 77.929, 74.222, 70.065, 61.918,
};

int upper_chi_col(double cl) {
  for (int i = 0; i < num_levels; i++) {
    if  (fabs(cl - u_levels[i]) < .0001)
      return i;
  }
  return -1;
}

// v = (h-1)(k-1)
double chi_critical_upper(int v, double confidence) {
  if (v < 1 || v > 100)
    return -1.0;
  v--;
  int col = upper_chi_col(confidence);
  if (col  < 0)
    return -1.0;

  return upper_table[index(100, num_levels, v, col)];
}

int lower_chi_col(double cl) {
  for (int i = 0; i < num_levels; i++) {
    if  (fabs(cl - l_levels[i]) < .0001)
      return i;
  }
  return -1;
}

double chi_critical_lower(int v, double confidence) {
  if (v < 1 || v > 100)
    return -1.0;
  v--;
  int col = lower_chi_col(confidence);
  if (col < 0)
    return -1.0;

  return lower_table[index(100, num_levels, v, col)];
}

