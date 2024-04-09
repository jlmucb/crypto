//
// Copyright 2024 John Manferdelli, All Rights Reserved.
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
// File: dilithium.h.h

#ifndef _KYBER_H__
#define _KYBER_H__

#include "crypto_support.h"
#include "symmetric_cipher.h"
using namespace std;

class kyber_parameters {
public:
  kyber_parameters(int ks);
  ~kyber_parameters();

  int n_;
  int k_;
  int du_;
  int dv_;
  int dt_;

  int q_;
  int eta1_;
  int eta2_;
  int beta_;
};

#endif
