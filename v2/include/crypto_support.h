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
// File: crypto_support.h

#ifndef _CRYPTO_SUPPORT_H__
#define _CRYPTO_SUPPORT_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <memory>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cmath>
#include <iostream>
#include <fstream>

#include <cstddef>

#ifndef byte
typedef unsigned char byte;
#endif

#ifndef int32_t
typedef int int32_t;
#endif

#ifndef int64_t
#ifdef __linux__
typedef long int int64_t;
#else
typedef long long int int64_t;
#endif
#endif

#ifndef uint32_t
typedef unsigned uint32_t;
#endif

#ifndef uint64_t
#ifdef __linux__
typedef long unsigned uint64_t;
#else
typedef long long unsigned uint64_t;
#endif
#endif

#ifndef NBITSINBYTE
#define NBITSINBYTE 8
#endif
#ifndef NBITSINUINT64
#define NBITSINUINT64 64
#endif

using std::string;
using std::ofstream;

extern ofstream logging_descriptor;
#define INFO "INFO: "
#define ERROR "ERROR: "
#define LOG(x) (logging_descriptor << x)

const int seconds_in_day = 86400;
const int seconds_in_minute = 60;
const int seconds_in_hour = 3600;
const double seconds_in_common_year = 365.0 * 86400;
const double seconds_in_leap_year = 366.0 * 86400;
const double seconds_in_gaussian_year = 365.2568983 * 86400;

class time_point {
 public:
  int year_;
  int month_;  // 1= January
  int day_in_month_;
  int hour_;
  int minutes_;
  double seconds_;

  time_point();
  bool time_now();
  bool add_interval_to_time(time_point& from, double seconds_later);
  void print_time();
  string* encodeTime();
  bool decodeTime(string encoded_time);
  bool time_point_to_unix_tm(struct tm* time_now);
  bool unix_tm_to_time_point(struct tm* time_now);
};
int compare_time_points(time_point& l, time_point& r);

class random_source {
public:
  bool initialized_;
  bool have_rd_rand_;
  int fd_;

  random_source();
  bool have_intel_rd_rand();
  bool start_random_source();
  int get_random_bytes(int n, byte* b);
  bool close_random_source();
};

void print_bytes(int n, byte* in);
void reverse_bytes(int size, byte* in, byte* out);
void reverse_bytes_in_place(int size, byte* b);
int bits_to_bytes(int n);
int bytes_to_bits(int n);
int bits_to_uint64(int n);
int uint64_to_bits(int n);

void little_to_big_endian_32(uint32_t* in, uint32_t* out);
void big_to_little_endian_32(uint32_t* in, uint32_t* out);
void little_to_big_endian_64(uint32_t* in, uint32_t* out);
void big_to_little_endian_64(uint32_t* in, uint32_t* out);
void little_to_big_endian_16(uint32_t* in, uint32_t* out);
void big_to_little_endian_16(uint32_t* in, uint32_t* out);

bool have_intel_rd_rand();
bool have_intel_aes_ni();

bool init_log(const char* log_file);
void close_log();
                        
uint64_t readRdtsc();
uint64_t calibrateRdtsc();

class file_util {
 public:
  bool initialized_;
  int fd_;
  bool write_;
  int bytes_in_file_;
  int bytes_read_;
  int bytes_written_;

  file_util();
  bool create(const char* filename);
  bool open(const char* filename);
  int bytes_in_file();
  int bytes_left_in_file();
  int bytes_written_to_file();
  void close();
  int read_a_block(int size, byte* buf);
  bool write_a_block(int size, byte* buf);
  int read_file(int size, byte* buf);
  bool write_file(int size, byte* buf);
};
#endif
