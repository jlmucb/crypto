// Copyright 2014-2024, John Manferdelli, All Rights Reserved.
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
// File: kyber.cc

#include "crypto_support.h"
#include "kyber.h"
#include "sha3.h"

using namespace std;

// This is the "vanilla" kyber, which is slow and has
// large keys.

// For 256 bit seal (ML-KEM-1024)
//    n =256, q=3329, k=4, eta1=2, eta2=2, du=11, dv=5

