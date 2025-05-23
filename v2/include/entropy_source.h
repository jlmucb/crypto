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
// File: entropy_source.h

#ifndef _CRYPTO_ENTROPY_SOURCE_H__
#define _CRYPTO_ENTROPY_SOURCE_H__
#include "crypto_support.h"
#include "sha256.h"

typedef int source_function(int, byte_t*);

class entropy_source {
public:
  string source_description_;
  double ent_per_sample_byte_;
  source_function* getentropy_;

  entropy_source(const char* description, double est, source_function pull) { 
    source_description_.assign(description);
    ent_per_sample_byte_ = est;
    getentropy_ = pull;
    };
  ~entropy_source(){};

};
#endif


