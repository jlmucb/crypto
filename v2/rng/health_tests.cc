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
// File: health_tests.cc

// Some of this code is derived from open source code published by Stephan Mueller
// in conjunction with jitter entropy downloaded in May, 2021, under the following license.
// License
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions
//   are met:
//   1. Redistributions of source code must retain the above copyright
//       notice, and the entire permission notice in its entirety,
//       including the disclaimer of warranties.
//   2. Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//   3. The name of the author may not be used to endorse or promote
//       products derived from this software without specific prior
//       written permission.
//  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
//  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
//  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
//  WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
//  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
//  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
//  OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
//  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
// OF THE USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.

#include <health_tests.h>
#include <probability_support.h>

apt::apt() {
  initialized_ = false;
  observations_ = 0;
  count_ = 0;
  base_ = 0;
  failure_ = false;
}

apt::~apt() {
}

void apt::init() {
  initialized_ = false;
}

void apt::reset(uint32_t current_delta) {
  count_ = 0;
  base_ = current_delta;
  observations_ = 0;
  failure_ = false;
}

void apt::insert(uint32_t current_delta) {
  if (!initialized_) {
    initialized_ = true;
    reset(current_delta);
    }

  if (current_delta == base_) {
    count_++;

  if (count_ >= APT_CUTOFF)
      failure_ = true;
  }
  observations_++;
  if (observations_ >= APT_WINDOW_SIZE)
    reset(current_delta);
}

// Stuck Test is used as Repetition Count Test (RCT)
// specified in SP800-90B section 4.4.1. Instead of counting identical
// back-to-back values, the input to the RCT is the counting of the stuck
// values during the generation of a noise output block.

// The RCT is applied with an alpha of 2^{-30} compliant to FIPS 140-2 IG 9.8.
// During the counting operation, the RNG always calculates the RCT
// cut-off value of C. If that value exceeds the allowed cut-off value,
// the Jitter RNG output block will be calculated completely but discarded at
// the end. The caller of the Jitter RNG is informed with an error code.

// Repetition Count Test as defined in SP800-90B section 4.4.1

rct::rct() {
  initialized_ = false;
  count_= 0;
  failure_ = false;
  osr_ = MIN_OSR;
  delta1_ = 0;
  delta2_ = 0;
  observations_ = 0;
}

rct::~rct() {
}

void rct::init() {
  initialized_ = false;
  count_= 0;
  failure_ = false;
  osr_ = MIN_OSR;
  delta1_ = 0;
  delta2_ = 0;
  observations_ = 0;
}

void rct::insert(uint32_t current_delta) {
  if (!initialized_) {
    initialized_ = true;
  }
   // If we have a count less than zero, a previous RCT round identified
   // a failure. Don't overwrite it.
  observations_++;
  if (count_ < 0)
    return;

  int s = stuck(current_delta);
  if (s) {
    count_++;
    // The cutoff value is based on the following consideration:
    // alpha = 2^-30 as recommended in FIPS 140-2 IG 9.8.
    // In addition, we require an entropy value H of 1/OSR as this
    // is the minimum entropy required to provide full entropy.
    // Note, we collect 64 * OSR deltas for inserting them into
    // the entropy pool which should then have (close to) 64 bits
    // of entropy.
    // Note, count_ (which equals to value B in the pseudo
    // code of SP800-90B section 4.4.1) starts with zero. Hence
    // we need to subtract one from the cutoff value as calculated
    // following SP800-90B.
    if (count_ >= (31 * osr_)) {
      count_ = 1<<30;
      failure_ = true;
    }
  } else {
    count_ = 0;
  }
}

// Check:
//   1st derivative of the jitter measurement (time delta)
//   2nd derivative of the jitter measurement (delta of time deltas)
//   3rd derivative of the jitter measurement (delta of delta of time deltas)
// All values must always be non-zero.
int rct::stuck(uint32_t current_delta) {
  uint32_t delta2 = current_delta - delta1_;
  uint32_t delta3 = delta1_ - delta2_;

  delta1_ = current_delta;
  delta2_ = delta2;
  if (current_delta == 0 || delta1_ == 0 || delta2_ == 0) {
    insert(1);
    return 1;
  } 
  insert(0);
  return 0;
}

//  NIST restart test

double binomial_value(int n, double p, int observed, bool tail_upper_direction) {
  double accum = 0.0;

  if (tail_upper_direction) {
    // upper tail
    for (int j = observed; j < n; j++) {
      accum += binomial_term(j, n, p);
    }
  } else {
    // lower tail
    for (int j = 0; j < observed; j++) {
      accum += binomial_term(j, n, p);
    }
  }
  return accum;
}

bool get_most_common_row_value(int m, int n, byte* a, int row, byte* value, int* count) {
  int counts[256];

  for (int i = 0; i < 256; i++)
    counts[i] = 0;

  for (int j = 0; j < n; j++) {
    counts[(int)a[index(m, n, row, j)]]++;
  }
  return false;
}

bool get_most_common_col_value(int m, int n, byte* a, int col, byte* value, int* count) {
  return false;
}

//    a is an m x n matrix of samples
//    h_min is the asserted entropy
//    Apply binomial test to rows and columns
//    return value is revised entropy, 0 means failure requiring restart
//    alpha = .000005
double restart_test(int m, int n, byte* a, double h_min, double alpha) {
  byte most_common_row_value = 0;
  int most_common_row_count = 0;
  byte most_common_col_value = 0;
  int most_common_col_count = 0;
  int highest_row = 0;
  int highest_col = 0;
  int highest_row_count = 0;
  int highest_col_count = 0;
  int row, col;
  byte value;
  int count = 0;
  double h_c = h_min;
  double h_r = h_min;
  double h_t;

  double t;
  for (row = 0; row < m; row++) {
    if (!get_most_common_row_value(m, n, a, row, &most_common_row_value,
                &most_common_row_count))
    return 0.0;
    if (most_common_row_count > highest_row_count) {
      highest_row_count = most_common_row_count;
      highest_row = row;
    }
    h_t = ((double)most_common_row_count) / ((double) m);
    if (h_t < h_r)
      h_r = h_t;
  }

  for (col = 0; col < m; col++) {
    if (!get_most_common_col_value(m, n, a, col, &most_common_col_value,
                &most_common_col_count))
      return 0.0;
    if (most_common_col_count > highest_col_count) {
      highest_col_count = most_common_col_count;
      highest_col = col;
    }
    h_t = ((double)most_common_col_count) / ((double) n);
    if (h_t < h_c)
      h_c = h_t;
  }

  double p = pow(2.0, -h_min);
  // for sanity check only need to test highest
  t = binomial_value(m, p, highest_row_count, true);
  if (t < alpha)
    return 0.0;
  t = binomial_value(n, p, highest_col_count, true);

  if (t < alpha)
    return 0.0;
  if (h_r <= h_c)
    return h_r;
  return h_c;
}

