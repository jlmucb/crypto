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
// File: entropy_collection.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "probability_support.h"
#include "entropy_accumulate.h"
#include "entropy_source.h"
#include "sha256.h"


entropy_accumulate::entropy_accumulate() {
  current_entropy_in_pool_= 0.0;
  current_size_pool_ = 0;
  pool_size_ = MAXPOOL_SIZE;
  memset(pool_, 0, MAXPOOL_SIZE);
}

entropy_accumulate::~entropy_accumulate() {
  current_entropy_in_pool_= 0.0;
  current_size_pool_ = 0;
  pool_size_ = MAXPOOL_SIZE;
  memset(pool_, 0, MAXPOOL_SIZE);
}

void entropy_accumulate::mix_entropy() {
  sha256 hash;
  
  hash.init();
  hash.add_to_hash(current_size_pool_, pool_);
  hash.finalize();
  hash.get_digest(sha256::DIGESTBYTESIZE, pool_);
  current_size_pool_ = sha256::DIGESTBYTESIZE;
}

//  For n_in bits or noise source, calculate output as follows:
//    n_in is number of bits of entropy in pool, current is entropy in pool
//    Let p_{high} = 2^{-h_{in}} and p_{low} = {\frac {1- p_{high}} {2^{n_{in}-1}}}
//    n = min(n_{out}, nw)
//    t= 2^{n_{in}-n}p_{low} + p_{high}
//    u= 2^{n_{in}-n} + sqrt{2n(2^{n_{in}-n})ln(2)}
//    w = u p_{low}
//    update is -lg(max(t,w))
//
// Best to use sha-3 since nw=1024 for it

double entropy_estimate_from_samples(int n_in, int n_out, int nw, double h_in) {
  double p_high = pow(2.0, -h_in);
  double p_low = (1.0 - p_high) / (pow(2.0, (double)n_in) - 1.0);
  int n = 0;
  if (n_out >= nw)
    n = nw;
  else
    n = n_out;
  double t1 = pow(2.0, (double)(n_in - n));
  double t = t1*p_low + p_high;
  double u = t1 + sqrt(2.0 * ((double)n) * t1 * log(2));
  double w = u * p_low;
  double h_out;
  if (t >= w)
    h_out = -(log(t) / log(2.0));
  else
    h_out = -(log(w) / log(2.0));
  if (h_out > ((double)n))
    h_out = (double) n;
  return h_out;
}

bool entropy_accumulate::add_samples(int num_samples, byte* samples, double est_ent_per_byte) {
  // copy samples into buffer, compress if we read pool size
  int samples_remaining = num_samples;
  int samples_used_so_far = 0;
  int k = 0;

  while (samples_remaining > 0) {
    if (current_size_pool_ >= pool_size_)
      mix_entropy();
    if (current_size_pool_ >= pool_size_)
      return false;
    int space_left_in_pool = pool_size_ - current_size_pool_;
    if (samples_remaining < space_left_in_pool)
      k = samples_remaining;
    else
      k = space_left_in_pool;
    memcpy(&pool_[current_size_pool_], &samples[samples_used_so_far], k);
    samples_used_so_far += k;
    samples_remaining -= k;
    current_size_pool_ += k;
    current_entropy_in_pool_ = current_entropy_in_pool_ + ((double)k) * est_ent_per_byte;
  }
  return true;
}

double entropy_accumulate::entropy_estimate() {
  return current_entropy_in_pool_;
}

bool entropy_accumulate::empty_pool(int* size_of_output, byte* data, double* ent) {
  if (current_size_pool_ > *size_of_output)
    return false;
  memcpy(data, pool_, current_size_pool_);
  *size_of_output = current_size_pool_;
  *ent = entropy_estimate();
  current_size_pool_ = 0;
  current_entropy_in_pool_= 0.0;
  return true;
}
