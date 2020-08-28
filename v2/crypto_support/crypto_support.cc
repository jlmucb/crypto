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
// File: crypto_support.cc

#include "crypto_support.h"
#include "gtest/gtest.h"
#include <gflags/gflags.h>
#include <stdio.h>
#include "support.pb.h"
#include <cmath>

time_point::time_point() {
  year_ = 0;
  month_ = 0;
  day_in_month_ = 0;
  hour_ = 0;
  minutes_ = 0;
  seconds_ = 0.0;
}

bool time_point::time_now() {
  time_t now;
  struct tm current_time;

  time(&now);
  gmtime_r(&now, &current_time);
  if (!unix_tm_to_time_point(&current_time))
    return false;
  return true;
}

bool time_point::add_interval_to_time(time_point& from, double seconds_later) {
  return true;
}

const char* s_months[] = {
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December"
};
void time_point::print_time() {
  int m = month_ - 1;
  if (m < 0 || m > 11)
    return;
  printf("%d %s %d, %02d:%02d:%lfZ", day_in_month_, s_months[m], year_,
      hour_, minutes_, seconds_);
}

string* time_point::encodeTime() {
  return nullptr;
}

bool time_point::decodeTime(string encoded_time) {
  return true;
}

bool time_point::time_point_to_unix_tm(struct tm* time_now) {
  return true;
}

bool time_point::unix_tm_to_time_point(struct tm* the_time) {
  year_ = the_time->tm_year + 1900;
  month_ = the_time->tm_mon + 1;
  day_in_month_ = the_time->tm_mday;
  hour_ = the_time->tm_hour;
  minutes_ = the_time->tm_min;
  seconds_ = the_time->tm_sec;
  return true;
}

int compare_time_points(time_point& l, time_point& r) {
  return 0;
}

int bits_to_bytes(int n) {
  return NBITSINBYTE * n;
}

int bytes_to_bits(int n) {
  return (n + NBITSINBYTE - 1) / NBITSINBYTE;
}

int bits_to_uint64(int n) {
  return NBITSINUINT64 * n;
}

int uint64_to_bits(int n) {
  return (n + NBITSINUINT64 - 1) / NBITSINUINT64;
}

random_source::random_source() {
  initialized_ = false;
  have_rd_rand_ = have_intel_rd_rand();
}

bool random_source::have_intel_rd_rand() {
  return have_rd_rand_;
}

bool random_source::start_random_source() {
  fd_ = open("/dev/urandom", O_RDONLY);
  initialized_ = fd_ > 0;
  return initialized_;
}

#define HAVE_RD_RAND
int random_source::get_random_bytes(int n, byte* b) {
  if (!initialized_)
    return -1;
#ifdef HAVE_RD_RAND
  int m = n;
  if (have_rd_rand_) {
    uint32_t out;

    while (m > 0) {
      asm volatile(
          "\trdrand %%edx\n"
          "\tmovl   %%edx, %[out]\n"
          : [out] "=m"(out)::"%edx");
      memcpy(b, (byte*)&out, sizeof(uint32_t));
      m -= sizeof(uint32_t);
      b += sizeof(uint32_t);
    }
    return n;
  }
#endif
  return read(fd_, b, (ssize_t)n);
}

bool random_source::close_random_source() {
  if (!initialized_)
    return true;
  close(fd_);
  initialized_ = false;
  return true;
}

void print_bytes(int n, byte* in) {
  int i;

  for(i = 0; i < n; i++) {
    printf("%02x",in[i]);
    if ((i%32)== 31)
      printf("\n");
  }
  if ((i%32) != 0)
    printf("\n");
}

void reverse_bytes(int size, byte* in, byte* out) {
  for (int i = 0; i < size; i++)
    out[size - 1 - i] = in[i];
}

void reverse_bytes_in_place(int size, byte* b) {
  byte t;

  for (int i = 0; i < (size / 2); i++) {
    t = b[size - 1 - i];
    b[size - 1 - i] = b[i];
    b[i] = t;
  }
}

void little_to_big_endian_32(uint32_t* in, uint32_t* out) {
  reverse_bytes(sizeof(uint32_t), (byte*) in, (byte*) out);
}

void big_to_little_endian_32(uint32_t* in, uint32_t* out) {
  reverse_bytes(sizeof(uint32_t), (byte*) in, (byte*) out);
}

void little_to_big_endian_64(uint32_t* in, uint32_t* out) {
  reverse_bytes(sizeof(uint64_t), (byte*) in, (byte*) out);
}

void big_to_little_endian_64(uint32_t* in, uint32_t* out) {
  reverse_bytes(sizeof(uint64_t), (byte*) in, (byte*) out);
}

void little_to_big_endian_16(uint32_t* in, uint32_t* out) {
  reverse_bytes(sizeof(uint16_t), (byte*) in, (byte*) out);
}

void big_to_little_endian_16(uint32_t* in, uint32_t* out) {
  reverse_bytes(sizeof(uint16_t), (byte*) in, (byte*) out);
}

bool have_intel_rd_rand() {
  uint32_t arg = 1;
  uint32_t rd_rand_enabled;

  asm volatile(
      "\tmovl    %[arg], %%eax\n"
      "\tcpuid\n"
      "\tmovl    %%ecx, %[rd_rand_enabled]\n"
      : [rd_rand_enabled] "=m"(rd_rand_enabled)
      : [arg] "m"(arg)
      : "%eax", "%ebx", "%ecx", "%edx");
  if (((rd_rand_enabled >> 30) & 1) != 0) {
    return true;
  }
  return false;
}

bool have_intel_aes_ni() {
  uint32_t arg = 1;
  uint32_t rd_aesni_enabled;

  asm volatile(
      "\tmovl    %[arg], %%eax\n"
      "\tcpuid\n"
      "\tmovl    %%ecx, %[rd_aesni_enabled]\n"
      : [rd_aesni_enabled] "=m"(rd_aesni_enabled)
      : [arg] "m"(arg)
      : "%eax", "%ebx", "%ecx", "%edx");
  if (((rd_aesni_enabled >> 25) & 1) != 0) {
    return true;
  }
  return false;
}

bool init_log(const char* log_file) {
  return true;
}

void close_log() {
}

uint64_t readRdtsc() {
  uint64_t out;
  uint64_t* ptr_out = &out;

  asm volatile(
      "\tmovq   %[ptr_out], %%rcx\n"
      "\trdtsc\n"
      "\tmovl   %%eax, (%%rcx)\n"
      "\tmovl   %%edx, 4(%%rcx)\n"
      :
      : [ptr_out] "m"(ptr_out)
      : "memory", "cc", "%eax", "%edx", "%rcx");
  return out;
}

uint64_t calibrateRdtsc() {
  time_t start, end;
  uint64_t start_cycles, end_cycles;
  uint64_t cps;

  for (;;) {
    start_cycles = readRdtsc();
    time(&start);
    sleep(2);
    end_cycles = readRdtsc();
    time(&end);
    double delta = difftime(end, start);
    if (start_cycles < end_cycles) {
      cps = (uint64_t)(((double)(end_cycles - start_cycles)) / delta);
      break;
    }
  }
  return cps;
}

file_util::file_util() {
  fd_ = -1;
  initialized_ = false;
  write_ = false;
  bytes_in_file_ = 0;
  bytes_read_ = 0;
  bytes_written_ = 0;
}

bool file_util::create(const char* filename) {
  return initialized_;
}

bool file_util::open(const char* filename) {
  return true;
}

int file_util::bytes_in_file() {
  return 0;
}

int file_util::bytes_left_in_file() {
  return 0;
}

int file_util::bytes_written_to_file() {
  return 0;
}

void file_util::close() {
}

int file_util::read_a_block(int size, byte* buf) {
  return 0;
}

bool file_util::write_a_block(int size, byte* buf) {
  return true;
}

int file_util::read_file(int size, byte* buf) {
  return 0;
}

bool file_util::write_file(int size, byte* buf) {
  return true;
}

