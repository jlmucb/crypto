// Copyright 2014 John Manferdelli, All Rights Reserved.
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
// File: entropy_series.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include "crypto_support.h"
#include "support.pb.h"
#include <unistd.h>
#include <stdio.h>
#include <math.h>

DEFINE_bool(debug, false, "Debug");
DEFINE_string(num_samples, "1000", "number of samples");
DEFINE_string(interval, "1000", "interval in us");
DEFINE_string(output_file, "tick_difference_output.bin", "output file");

// entropy series generates time series differences
int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  if (!init_crypto()) {
    printf("init_crypto failed\n");
    return 1;
  }

  int interval, num_samples;
  sscanf(FLAGS_interval.c_str(), "%d", &interval);
  sscanf(FLAGS_num_samples.c_str(), "%d", &num_samples);
  uint64_t num_ticks_per_sec = calibrate_rdtsc();
  printf("interval: %d us, number of samples: %d, number of ticks per second: %lu\n", 
    interval, num_samples, num_ticks_per_sec);
  int fd = creat(FLAGS_output_file.c_str(), S_IRWXU | S_IRWXG);
  if (fd < 0) {
    printf("Can't create %s\n", FLAGS_output_file.c_str());
    return 1;
  }

  uint64_t last = read_rdtsc();
  uint64_t current = 0ULL;
  uint64_t difference= 0ULL;

  uint32_t diffs[num_samples];
  for (int i = 0; i < num_samples; i++) {
    usleep((uint32_t)interval);
    current = read_rdtsc();
    difference = current - last;
    last = current;
    difference = difference & 0x00000000000000ffULL;
    diffs[i] = (uint32_t) difference;
    if (FLAGS_debug) {
      printf("%d: %u\n", i, (uint32_t)difference);
    }
    write(fd, &difference, sizeof(uint64_t));
  }
  close(fd);

  uint64_t sum = 0ULL;
  for (int i = 0; i < num_samples; i++) {
    sum += (uint64_t) diffs[i];
  }
  double mean = ((double)sum) / ((double)num_samples);
  double t;
  double var = 0.0;
  for (int i = 0; i < num_samples; i++) {
    t = mean - (double) diffs[i];
    var += t * t;
  }
  var /= (double) (num_samples - 1);
  double sigma = sqrt(var);
  printf("mean: %8.3lf, variance: %8.3lf, sigma: %8.3lf\n", mean, var, sigma);

  int nbins = 1<<8;
  int bins[nbins];
  for(int i = 0; i < nbins; i++) {
    bins[i]= 0;
  }
  for (int i = 0; i < num_samples; i++) {
    if (diffs[i] >= nbins)
      continue;
    bins[diffs[i]]++;
  }

  double p;
  double shannon_ent = 0.0;
  for(int i = 0; i < nbins; i++) {
    if (bins[i] == 0)
      continue;
    p = ((double) bins[i]) / ((double) num_samples);
    shannon_ent += p * log(p);
  }
  shannon_ent = - shannon_ent / log(2.0);
  printf("nbins: %d, Shannon entropy: %8.4lf\n", nbins, shannon_ent);

  close_crypto();
  printf("\n");
  return 0;
}
