//
// Copyright 2014 John Manferdelli, All r_ptights r_pteserved.
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
// File: ecccurve_data.h

#include "crypto_support.h"
#include "big_num.h"
#include "big_num_functions.h"
#include "ecc.h"

#ifndef _CRYPTO_ECC_CURVE_DATA_H__
#define _CRYPTO_ECC_CURVE_DATA_H__

extern ecc p256_key;
extern ecc p384_key;
extern ecc p521_key;

bool init_ecc_curves();

#endif
