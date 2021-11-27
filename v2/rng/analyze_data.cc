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
DEFINE_string(graph_file_name, "graph.bin", "Graph file name");
DEFINE_int32(input_format, 1, "Input format");

// A chi-square with large degrees of freedom, df, is approximately normal with mean df and variance 2𝜈.
// erf(x) = 2/sqrt(pi) int_0^x exp(-t*t) dt
// Pr(chi^2>=x)
double chi_confidience(int df, double x) {
  double z = (x - ((double)df)) / sqrt((double)(2*df));
  return erf(z) / sqrt(2.0);
}

int num_lines(int sz, char* txt) {
  int num = 0;
  for (int i = 0; i < sz; i++) {
    if (txt[i] == '\n')
      num++;
  }
  return num;
}

bool is_num(char c) {
  return c>='0' && c <='9';
}

bool get_values(int sz, char* txt_data, int* num_samples, uint32_t* samples) {
  char* front = txt_data;
  char* back = &txt_data[sz];
  char* next_nl = nullptr;
  unsigned int val;
  int k = 0;

  while (front < back && k < *num_samples) {
    next_nl = front;
    while (*next_nl != '\n' && next_nl < back)
      next_nl++;

    if (next_nl > front && is_num(*front)) {
      sscanf(front, "%u\n", &val);
      samples[k++] = val;
    }
    front =  next_nl + 1;
  }
  *num_samples = k;
  return true;
}

char* skip(char* p, char* back) {
  while(*(p++) != ',' && p < back);
  while(*(p++) != ',' && p < back);
  while (*p == ' ' && p < back) p++;
  if (p >= back)
    return nullptr;
  return p;
}

bool get_last_value_on_line(int sz, char* txt_data, int* num_samples, uint32_t* samples) {
  char* front = txt_data;
  char* back = &txt_data[sz];
  char* next_nl = nullptr;
  unsigned int val;
  int k = 0;
  char* p;

  while (front < back && k < *num_samples) {
    next_nl = front;
    while (*next_nl != '\n' && next_nl < back)
      next_nl++;

    if (next_nl > front && (next_nl < back && (p=skip(front, next_nl)) != nullptr)) {
      if (!is_num(*front)) {
        front =  next_nl + 1;
        continue;
      }
      sscanf(p, "%u\n", &val);
      samples[k++] = val;
    }
    front =  next_nl + 1;
  }
  *num_samples = k;
#if 0
  if (FLAGS_print_all) {
    for (int i = 0; i < k; i++) {
      if ((i%16)==15) {
        printf("%3d\n", samples[i]);
      } else {
        printf("%3d, ", samples[i]);
      }
    }
    printf("\n");
  }
#endif
  return true;
}

bool to_general_graph(int nbins, uint32_t* bins, double* x, double* y) {
  for (int i = 0; i < nbins; i++) {
    x[i] = (double)i;
    y[i] = (double)bins[i];
  }
  return true;
}

bool range(int num_samples, uint32_t* samples, uint32_t* max, uint32_t* min) {
  *min = 1>>30;
  *max = 0;

  for (int i = 0; i < num_samples; i++) {
    if (samples[i] > *max)
      *max = samples[i];
    if (samples[i] < *min)
      *min = samples[i];
  }
  return true;
}


int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  int result = 0;

  init_crypto();

  // Read data
  int num_samples = 0;
  uint32_t* samples = nullptr;
  {
    file_util f;
    if (!f.open(FLAGS_data_file_name.c_str())) {
      printf("Can't open %s\n", FLAGS_data_file_name.c_str());
      return 1;
    }
    int sz = f.bytes_in_file();
    f.close();
    char txt_data[sz + 1];
    if (!f.read_file(FLAGS_data_file_name.c_str(), sz, (byte*)txt_data)) {
      printf("Can't read %s\n", FLAGS_data_file_name.c_str());
      return 1;
    }

    int max_num_samples = num_lines(sz, txt_data);
    num_samples = max_num_samples;
    samples = new uint32_t[num_samples];

    if (FLAGS_input_format == 2) {
      if (!get_values(sz, txt_data, &num_samples, samples)) {
        printf("Can't get values from %s\n", FLAGS_data_file_name.c_str());
        result = 1;
        delete []samples;
        return 1;
      }
    } else {
      if (!get_last_value_on_line(sz, txt_data, &num_samples, samples)) {
        printf("Can't get values from %s\n", FLAGS_data_file_name.c_str());
        result = 1;
        delete []samples;
        return 1;
      }
    }
  }

  uint32_t v_max = 0;
  uint32_t v_min = 0;
  range(num_samples, samples, &v_max, &v_min);
  printf("read %d values.  max: %d, min: %d.\n", num_samples, v_max, v_min);

  double s_ent = 0;
  double r_ent = 0;
  double m_ent = 0;
  double mean = calculate_uint32_mean(num_samples, samples);
  double var = calculate_uint32_variance(num_samples, samples, mean);
  double sigma = sqrt(var);
  printf("mean: %.3lf, variance: %.3lf, sigma: %.3lf\n", mean, var, sigma);

  int num_bits = 8;
  int nbins = 1<<num_bits;
  uint32_t bins[nbins];
  double prob[nbins];
  double v[nbins];
  double x[nbins], y[nbins];
  double corrected_variance = 0;
  double corrected_sigma = 0;
  zero_uint32_array(nbins, bins);
  zero_double_array(nbins, x);
  zero_double_array(nbins, y);
  zero_double_array(nbins, prob);
  double pr[nbins];
  double chi_value = 0.0;

  // keep values 255 or less
  for(int i = 0; i < num_samples; i++) {
    samples[i] &= (uint32_t)0xffff;
  }

  if (!bin_raw_data(num_samples, samples, nbins, bins)) {
    printf("Can't bin data\n");
    result = 1;
    goto done;
  }

  printf("Bins:\n");
  print_uint32_array(nbins, bins);

  if (!calculate_bin_probabilities(nbins, bins, prob)) {
    printf("Can't calculate bin probabilities\n");
    result = 1;
    goto done;
  }

  printf("probabilities:\n");
  print_double_array(nbins, prob);

  for (int i = 0; i < nbins; i++)
    v[i] = (double)i;

  corrected_variance = variance(nbins, mean, prob, v);
  corrected_sigma = sqrt(corrected_variance);
  printf("Corrected variance: %.3lf, corrected sigma: %.3lf\n", corrected_variance, corrected_sigma);

  if (!calculate_bin_entropies(num_samples, nbins, bins, &s_ent, &r_ent, &m_ent)) {
    printf("Can't calculate bin entropies\n");
    result = 1;
    goto done;
  }
  printf("shannon entropy: %.3lf, renyi entropy: %.3lf, min entropy: %.3lf\n", s_ent, r_ent, m_ent);

#if 1
  if (!to_general_graph(nbins, bins, x, y)) {
    printf("Can't convert to general graph format\n");
  }
  if (!write_general_graph_data(FLAGS_graph_file_name, nbins, x, y)) {
    printf("Can't write graph file %s\n", FLAGS_graph_file_name.c_str());
  }
#else
  if (!write_graph_data(FLAGS_graph_file_name, nbins, bins)) {
    printf("Can't write graph file %s\n", FLAGS_graph_file_name.c_str());
  }
#endif

  for (int i = 0; i < nbins; i++) {
    pr[i] = 1.0 / ((double) nbins);
  }
  if (!binned_chi_squared_test(num_samples, nbins, bins, pr, &chi_value)) {
    printf("Can't do chi squared\n");
  }

  {
    double t_s = chi_confidience(256, chi_value);
    printf("Chi squared: %lf, test statistic: %lf\n", chi_value, t_s);
    printf("With this distribution, the probability that the chi-square value is larger than this is %lf\n", 1.0-t_s);
  }


done:
  // clean up
  if (samples != nullptr) {
    delete []samples;
  }
  close_crypto();
  printf("\n");
  return result;
}
