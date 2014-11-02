//
// Copyright 2014 John Manferdelli, All Rights Reserved.
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
// Project: New Cloudproxy Crypto
// File: globals.cc for bignum

#include <google/gtest/gtest.h>
#include <google/gflags/gflags.h>
#include <stdio.h>
#include <string>
#include "conversions.h"
#include "bignum.h"
#include "util.h"

BigNum	Big_Zero(1, 0ULL);
BigNum	Big_One(1, 1ULL);
BigNum	Big_Two(1, 2ULL);
BigNum	Big_Three(1, 3ULL);
BigNum	Big_Five(1, 5ULL);
