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
// File: entropy_support.cc

#include <crypto_support.h>
#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include "entropy_support.h"

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
    difference = (difference / divisor) & mask;
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


