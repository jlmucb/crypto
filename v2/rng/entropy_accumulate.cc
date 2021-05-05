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

bool entropy_accumulate::add_samples(int num_samples, byte* samples, double est_ent_per_byte) {
  return true;
}

double entropy_accumulate::entropy_estimate() {
  return current_entropy_in_pool_;
}

bool entropy_accumulate::empty_pool(int* size_of_output, byte* data, double* ent) {
  return true;
}
