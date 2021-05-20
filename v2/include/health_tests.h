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
// File: health_tests.h

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
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
//  USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
//  DAMAGE.


#ifndef __HEALTH_TESTS_
#define __HEALTH_TESTS_
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef byte
typedef unsigned char byte;
#endif

#define APT_CUTOFF         325     // Taken from SP800-90B sec 4.4.2
#define APT_WINDOW_SIZE    512     // Data window size
#define APT_LSB             16
#define APT_WORD_MASK      (JENT_APT_LSB - 1)
#define MIN_OSR             1

class apt {
public:
  // Adaptive Proportion Test for a significance level of 2^-30
  bool initialized_;
  int observations_;  // Number of collected observations
  int count_;         // counter
  uint32_t base_;     // base reference
  bool failure_;

  apt();
  ~apt();
  void init();
  void reset(uint32_t current_delta);
  void insert(uint32_t current_delta);
  bool failed() {return failure_;};
};

class rct {
public:
  bool initialized_;
  int observations_;  // Number of collected observations
  uint32_t  delta1_;
  uint32_t  delta2_;
  int osr_;
  int count_;         // Number of stuck values
  bool failure_;
  rct();
  ~rct();
  void init();
  void insert(uint32_t current_delta);
  int stuck(uint32_t current_delta);
  bool failed() {return failure_;};
};

double restart_test(int m, int n, byte* a, double h_min, double alpha);
double binomial_value(int n, double p, int observed, bool tail_upper_direction);
#endif
