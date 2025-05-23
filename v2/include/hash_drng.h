// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: hash_drng.h

#ifndef _CRYPTO_HASH_DRNG_H__
#define _CRYPTO_HASH_DRNG_H__
#include "crypto_support.h"
#include "sha256.h"


// Hash drng
class hash_drng {
public:
  bool initialized_;
  int reseed_ctr_;
  double current_entropy_;
  int hash_byte_output_size_;
  int seed_len_bits_;
  int seed_len_bytes_;
  byte_t C_[64];
  byte_t V_[64];

  hash_drng();
  ~hash_drng();

  int get_reseed_counter() {return reseed_ctr_;};
  double current_entropy();
  bool init(int size_nonce, byte_t* nonce, int size_personalization,
            byte_t* personalization, int entropy_width, byte_t* entropy,
            double ent);
  void hash_gen(int num_requested_bits, byte_t* out);
  bool generate_random_bits(int num_bits_needed, byte_t* out,
          int n_add_in_bits, byte_t* add_in_bits);
};
#endif


