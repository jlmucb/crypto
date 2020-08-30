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
#include <support.pb.h>

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
  bool encodeTime(string* the_time);
  bool decodeTime(string& encoded_time);
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
bool hex_to_bytes(string& h, string* b);
bool bytes_to_hex(string& b, string* h);
bool base64_to_bytes(string& b64, string* b);
bool bytes_to_base64(string& b, string* b64);

void little_to_big_endian_32(uint32_t* in, uint32_t* out);
void big_to_little_endian_32(uint32_t* in, uint32_t* out);
void little_to_big_endian_64(uint64_t* in, uint64_t* out);
void big_to_little_endian_64(uint64_t* in, uint64_t* out);
void little_to_big_endian_16(uint16_t* in, uint16_t* out);
void big_to_little_endian_16(uint16_t* in, uint16_t* out);

void print_u64_array(int n, uint64_t* x);

int u64_array_to_bytes(int size_n, uint64_t* n, string* b);
int bytes_to_u64_array(string& b, int size_n, uint64_t* n);

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
  int read_file(char* filename, int size, byte* buf);
  bool write_file(char* filename, int size, byte* buf);
};

key_message* make_symmetrickey(const char* alg, const char* name, int bit_size,
                               const char* purpose, const char* not_before,
                               const char* not_after, string& secret);
key_message* make_rsakey(const char* alg, const char* name, int bit_size,
                           const char* purpose, const char* not_before,
                           const char* not_after, string& m,
                           string& e, string& d, string& p, string& q);
key_message* make_ecckey(const char* name, int bit_size, const char* purpose,
                         const char* not_before, const char* not_after,
                         const char * curve_name,
                         string& p,
                         string& secret_multiplier,
                         string& private_base_point_x,
                         string& private_base_point_y,
                         string& public_base_point_x,
                         string& public_base_point_y);

scheme_message* make_scheme(const char* name, const char* id,
  const char* encryption_alg, const char* encryption_key_name,
  int encryption_key_bit_size, const char* encryption_key_purpose,
  const char* encryption_key_not_before, const char* encryption_key_not_after,
  string& encryption_key_secret, const char* hmac_alg, int hmac_key_size,
  string& hmac_secret, string& nonce);

void print_binary_blob(binary_blob_message& m);
void print_encrypted_message(encrypted_message& m);
void print_signature_message(signature_message& m);
void print_rsa_public_parameters_message(rsa_public_parameters_message& m);
void print_ecc_public_parameters_message(ecc_public_parameters_message& m);
void print_rsa_private_parameters_message(rsa_private_parameters_message& m);
void print_ecc_private_parameters_message(ecc_private_parameters_message& m);
void print_hmac_parameters_message(hmac_parameters_message& m);
void print_key_message(key_message& m);
void print_scheme_message(scheme_message& m);
void print_crypto_signature_message(crypto_signature_message& m);
void print_cert_name_message(cert_name_message& m);
void print_cert_principal_name_message(cert_principal_name_message& m);
void print_cert_rsa_parameters_message(cert_rsa_parameters_message& m);
void print_cert_ecc_parameters_message(cert_ecc_parameters_message& m);
void print_cert_algorithm_message(cert_algorithm_message& m);
void print_cert_properties_message(cert_properties_message& m);
void print_certificate_message(certificate_message& m);

#endif
