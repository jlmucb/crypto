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
// File: hmac_drng.h

#ifndef _CRYPTO_HMAC_DRNG_H__
#define _CRYPTO_HMAC_DRNG_H__
#include "crypto_support.h"
#include "sha256.h"


// Hash drng
class hmac_drng {
public:
  bool initialized_;
  int reseed_ctr_;
  double current_entropy_;
  int hash_byte_output_size_;
  int seed_len_bits_;
  int seed_len_bytes_;
  byte K_[64];
  byte V_[64];

  hmac_drng();
  ~hmac_drng();

  int get_reseed_counter() {return reseed_ctr_;};
  double current_entropy();
  bool update(int size_data, byte* data);
  bool init(int size_nonce, byte* nonce, int size_personalization,
            byte* personalization, int entropy_width, byte* entropy,
            double ent);
  bool generate(int num_bits_needed, byte* out,
          int n_add_in_bytes, byte* add_in_bytes);
};
#endif


