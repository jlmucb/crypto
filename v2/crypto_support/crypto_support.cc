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
#include "support.pb.h"
#include <stdio.h>

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
  // This doesn't do leap years, seconds, month or other stuff... correctly
  year_ = from.year_;
  day_in_month_ = from.day_in_month_;
  month_= from.month_;
  minutes_= from.minutes_;
  hour_= from.hour_;
  seconds_= from.seconds_;

  int days = seconds_later / (double)seconds_in_day;
  seconds_later -= (double) (days * seconds_in_day);
  int yrs = days /365;
  days -= yrs * 365;
  year_ += yrs;
  int months = days / 30; // not right;
  days -= months * 30;
  month_ +=  months;
  day_in_month_ += days;
  int mins = (int)seconds_later / 60.0;
  seconds_later -= (double) (mins * 60);
  int hrs = (int)mins / 60.0;
  mins -= hrs * 60;
  hour_ += hrs;
  minutes_ += mins;
  seconds_+= seconds_later;
  // now fix overflows
  if (seconds_ >= 60.0) {
    seconds_ -= 60.0;
    minutes_ += 1;
  }
  if (minutes_ >= 60) {
    minutes_ -= 60;
    hour_ += 1;
  }
  if (hour_ >= 24) {
    day_in_month_ += 1;
    hour_ -= 24;
  }
  if(day_in_month_ > 30) {
    month_ += 1;
    day_in_month_ -= 30;
  }
  if (month_ > 12) {
    year_ += 1;
    month_ -= 12;
  }
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

bool time_point::encodeTime(string* the_time) {
  int m = month_ - 1;
  if (m < 0 || m > 11)
    return false;
  char time_str[256];
  *time_str = '\0';
  snprintf(time_str,255, "%d %s %d, %02d:%02d:%lfZ", day_in_month_, s_months[m], year_,
      hour_, minutes_, seconds_);
  m = strlen(time_str);
  *the_time = time_str;
  return true;
}

const char* m_months[12] = {
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December"
};
int month_from_name(char* mn) {
  for(int i = 0; i < 12; i++) {
    if (strcmp(mn, m_months[i]) == 0)
      return i;
  }
  return -1;
}
bool time_point::decodeTime(string& encoded_time) {
  int dm, yr, hr, min;
  double sec;
  char s[20];
  sscanf(encoded_time.c_str(), "%d %s %d, %02d:%02d:%lfZ", &dm, s, &yr,
      &hr, &min, &sec);
  int mm = month_from_name(s);
  if (mm < 0)
   return false;
  mm++;
  year_ = yr;
  month_ = mm;
  day_in_month_ = dm;
  hour_ = hr;
  minutes_ = min;
  seconds_ = sec;
  return true;
}

bool time_point::time_point_to_unix_tm(struct tm* time_now) {
  return false;
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
  if (l.year_ > r.year_)
    return 1;
  if (l.year_ < r.year_)
    return -1;
  if (l.month_ > r.month_)
    return 1;
  if (l.month_ < r.month_)
    return -1;
  if (l.day_in_month_ > r.day_in_month_)
    return 1;
  if (l.day_in_month_ < r.day_in_month_)
    return -1;
  if (l.hour_ > r.hour_)
    return 1;
  if (l.hour_ < r.hour_)
    return -1;
  if (l.minutes_ > r.minutes_)
    return 1;
  if (l.minutes_ < r.minutes_)
    return -1;
  if (l.seconds_ > r.seconds_)
    return 1;
  if (l.seconds_ < r.seconds_)
    return -1;
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

static byte s_hex_values1[10] = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9
};
static byte s_hex_values2[6] = {
  10, 11, 12, 13, 14, 15
};
byte hex_value(char a) {
  if (a >= '0' && a <= '9')
    return s_hex_values1[a - '0'];
  if (a >= 'A' && a <= 'F')
    return s_hex_values2[a - 'A'];
  if (a >= 'a' && a <= 'f')
    return s_hex_values2[a - 'a'];
  return 0;
}  

bool valid_hex(char* s) {
  char a;
  while (*s != '\0') {
    a = *(s++);
    if (a >= '0' && a <= '9')
      continue;
    if (a >= 'A' && a <= 'F')
      continue;
    if (a >= 'a' && a <= 'f')
      continue;
    return false;
  }
  return true;
}

bool hex_to_bytes(string& h, string* b) {
  b->clear();
  if (!valid_hex((char*)h.c_str()))
    return false;
  int h_size = strlen(h.c_str());
  // if odd first 4 bits is 0
  if (((int)b->capacity()) < (h_size + 1) / 2)
    return false;
  byte b1, b2;
  int k;
  if ((h_size % 2) != 0) {
    b1 = 0;
    b2 = hex_value(h[0]);
    k = 1;
    b->append(1, (char)b2);
  } else {
    k = 0;
  }
  for (int i = k; i < h_size; i += 2) {
    b1 = hex_value(h[i]);
    b2 = hex_value(h[i + 1]);
    b1 = (b1 << 4) | b2;
    b->append(1, b1);
  }
  return true;
}

static char s_hex_chars[16] = {
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};
char hex_char(byte b) {
  if (b > 16)
    return '0';
  return s_hex_chars[b];
}

bool bytes_to_hex(string& b, string* h) {
  // always returns even number of hex characters
  h->clear();
  int b_size = b.size();
  if (((int)h->capacity()) < 2 * b_size + 1)
    return false;
  char c1, c2;
  byte b1, b2;
  for (int i = 0; i < b_size; i++) {
    b1 = (b[i] >> 4) & 0x0f;
    b2 = b[i] & 0x0f;
    c1 = hex_char(b1);
    c2 = hex_char(b2);
    h->append(1, c1);
    h->append(1, c2);
  }
  h->append(1, '\0');
  return true;
}

static const char* web_safe_base64_characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
bool valid_base64(char* s) {
  char a;
  while (*s != '\0') {
    a = *(s++);
    if (a >= '0' && a <= '9')
      continue;
    if (a >= 'A' && a <= 'Z')
      continue;
    if (a >= 'a' && a <= 'z')
      continue;
    if (a == '-' || a == '_' || a == '=')
      continue;
    return false;
  }
  return true;
}
byte base64_value(char a) {
  for (int i = 0; i < (int)strlen(web_safe_base64_characters); i++) {
    if (a == web_safe_base64_characters[i])
      return i;
  }
  return -1;
}
char base64_char(byte a) {
  if (a >= 0x3f)
   return ' ';
  return web_safe_base64_characters[(int)a];
}
bool base64_to_bytes(string& b64, string* b) {
  if (!valid_base64((char*)b64.c_str()))
    return false;
  b->clear();
  int b64_size = strlen(b64.c_str());
  if (((int)b->capacity()) < ((b64_size / 4) * 3 + 1))
    return false;
  int i;
  byte x1, x2, x3, x4, z;
  for (i = 0; i < (b64_size - 4); i += 4) {
    x1 = base64_value(b64[i]);
    x2 = base64_value(b64[i + 1]);
    x3 = base64_value(b64[i + 2]);
    x4 = base64_value(b64[i + 3]);
    z = (x1 << 2) | (x2 >> 4);
    b->append(1, (char)z);
    x2 &= 0x0f;
    z = (x2 << 4) | (x3 >> 2);
    b->append(1, (char)z);
    x3 &= 0x03;
    z = (x3 << 6) | x4;
    b->append(1, (char)z);
  }
  // the possibilities for the remaining base64 characters are
  //  c1 (6 bits), c2 (2 bits), =, =
  //  c1 (6 bits), c2 (6 bits), c3 (4bits), =
  // sanity check
  if ((b64_size - i) != 4)
    return false;
  if (b64[b64_size - 1] == '=' && b64[b64_size - 2] != '=') {
    x1 = base64_value(b64[b64_size - 4]);
    x2 = base64_value(b64[b64_size - 3]);
    x3 = base64_value(b64[b64_size - 2]);
    z = (x1 << 2) | (x2 >> 4);
    b->append(1, (char)z);
    z = (x2 << 4) | x3;
    b->append(1, (char)z);
  } else if (b64[b64_size - 1] == '=' && b64[b64_size - 2] == '=') {
    x1 = base64_value((char)b64[b64_size - 4]);
    x2 = base64_value((char)b64[b64_size - 3]);
    z = (x1 << 2) | x2;
    b->append(1, (char)z);
  } else {
    x1 = base64_value((char)b64[b64_size - 4]);
    x2 = base64_value((char)b64[b64_size - 3]);
    x3 = base64_value((char)b64[b64_size - 2]);
    x4 = base64_value((char)b64[b64_size - 1]);
    z = (x1 << 2) | (x2 >> 4);
    b->append(1, (char)z);
    x2 &= 0x0f;
    z = (x2 << 4) | (x3 >> 2);
    b->append(1, (char)z);
    x3 &= 0x03;
    z = (x3 << 6) | x4;
    b->append(1, (char)z);
  }
  return true;
}

bool bytes_to_base64(string& b, string* b64) {
  b64->clear();
  int b_size = b.size();
  byte x1, x2, x3, z;
  char c;
  int i;
  for (i = 0; i < (b_size - 3); i += 3) {
    x1 = b[i];
    z = x1 >> 2;
    c = base64_char(z);
    b64->append(1, c);
    x2 = b[i + 1];
    z = (x1 & 0x03) << 4 | x2>>4;
    c = base64_char(z);
    b64->append(1, c);
    x3 = b[i + 2];
    z = (x2 & 0x0f) << 2 | x3 >> 6; 
    c = base64_char(z);
    b64->append(1, c);
    z = x3 & 0x3f;
    c = base64_char(z);
    b64->append(1, c);
  }
  // there can be 1, 2 or 3 bytes left
  if ((b_size - i) == 1) {
    x1 = b[i];
    z = x1 >> 2;
    c = base64_char(z);
    b64->append(1, c);
    z = (x1 & 0x03);
    c = base64_char(z);
    b64->append(1, c);
    b64->append(2, '=');
  } else if ((b_size - i) == 2) {
    x1 = b[i];
    x2 = b[i + 1];
    z = x1 >> 2;
    c = base64_char(z);
    b64->append(1, c);
    z = (x1 & 0x03) << 4 | x2 >> 4;
    c = base64_char(z);
    b64->append(1, c);
    z =  x2 & 0x0f;
    c = base64_char(z);
    b64->append(1, c);
    b64->append(1, '=');
  } else if ((b_size - i) == 3) {
    x1 = b[i];
    x2 = b[i + 1];
    x3 = b[i + 2];
    z = x1 >> 2;
    c = base64_char(z);
    b64->append(1, c);
    z = (x1 & 0x03) << 4 | x2 >> 4;
    c = base64_char(z);
    b64->append(1, c);
    z =  (x2 & 0x0f) << 2 | x3 >> 6;
    c = base64_char(z);
    b64->append(1, c);
    z =  x3 & 0x03f;
    c = base64_char(z);
    b64->append(1, c);
  }
  b64->append(1, '\0');
  return true;
}

random_source::random_source() {
  initialized_ = false;
  have_rd_rand_ = have_intel_rd_rand();
}

bool random_source::have_intel_rd_rand() {
  return have_rd_rand_;
}

bool random_source::start_random_source() {
  fd_ = ::open("/dev/urandom", O_RDONLY);
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

void little_to_big_endian_64(uint64_t* in, uint64_t* out) {
  reverse_bytes(sizeof(uint64_t), (byte*) in, (byte*) out);
}

void big_to_little_endian_64(uint64_t* in, uint64_t* out) {
  reverse_bytes(sizeof(uint64_t), (byte*) in, (byte*) out);
}

void little_to_big_endian_16(uint16_t* in, uint16_t* out) {
  reverse_bytes(sizeof(uint16_t), (byte*) in, (byte*) out);
}

void big_to_little_endian_16(uint16_t* in, uint16_t* out) {
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

ofstream logging_descriptor;
bool init_log(const char* log_file) {
  time_point tp;
  tp.time_now();
  string the_time;
  if (!tp.encodeTime(&the_time))
    return false;
  logging_descriptor.open(log_file);
  LOG(INFO) << "Log file " << log_file << " opened " << the_time << ".\n";
  return true;
}

void close_log() {
  time_point tp;
  tp.time_now();
  string the_time;
  tp.encodeTime(&the_time);
  LOG(INFO) << "Log file closed " << the_time << ".\n";
  logging_descriptor.close();
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
  write_ = true;
  fd_ = creat(filename, S_IRWXU | S_IRWXG);
  initialized_ = fd_ > 0;
  return initialized_;
}

bool file_util::open(const char* filename) {
  struct stat file_info;
  if (stat(filename, &file_info) != 0)
    return false;
  if (!S_ISREG(file_info.st_mode))
    return false;
  bytes_in_file_ = (int)file_info.st_size;
  fd_ = ::open(filename, O_RDONLY);
  initialized_ = fd_ > 0;
  write_ = false;
  return initialized_;
}

int file_util::bytes_in_file() {
  return bytes_in_file_;
}

int file_util::bytes_left_in_file() {
  return bytes_in_file_ - bytes_read_;
}

int file_util::bytes_written_to_file() {
  return bytes_written_;
}

void file_util::close() {
  ::close(fd_);
  initialized_ = false;
}

int file_util::read_a_block(int size, byte* buf) {
  if (!initialized_)
    return -1;
  if (write_)
    return -1;
  bytes_read_ += size;
  return read(fd_, buf, size);
}

bool file_util::write_a_block(int size, byte* buf) {
  if (!initialized_)
    return false;
  if (!write_)
    return false;
  bytes_written_ += size;
  return write(fd_, buf, size) > 0;
}

int file_util::read_file(char* filename, int size, byte* buf) {
  if (!open(filename))
    return -1;
  if (bytes_in_file_ < size) {
      close();
      return -1;
  }
  int n = read_a_block(size, buf);
  close();
  return n;
}

bool file_util::write_file(char* filename, int size, byte* buf) {
  if (!create(filename))
    return -1;
  int n = write_a_block(size, buf);
  close();
  return n > 0;
}

void print_u64_array(int n, uint64_t* x) {
  for (int i = (n - 1); i >= 0; i--)
    printf("%016llx ", x[i]);
}

int u64_array_to_bytes(int size_n, uint64_t* n, string* b) {
  int real_size_n = size_n;

  b->clear();
  for (int i = size_n; i > 0; i--) {
    if (n[i - 1] != 0ULL)
      break;
    real_size_n--;
  }
  uint64_t little_endian = 0ULL;
  for (int i = (real_size_n - 1); i >= 0; i--) {
    little_endian = 0ULL;
#ifndef BIG_ENDIAN
    little_endian = n[i];
#else
    big_to_little_endian_64(&n[i], &little_endian);
#endif
    byte* p = (byte*) &little_endian;
    for (int j = 0; j < (int)sizeof(uint64_t); j++)
      b->append(1, (char)p[j]);
  }
  return b->size();
}

int bytes_to_u64_array(string& b, int size_n, uint64_t* n) {
  int real_size_b = (int)b.size();
  for (int i = 0; i < (int)b.size(); i++) {
    if (b[i] != 0)
      break;
    real_size_b--;
  }
  if (real_size_b == 0) {
    n[0] = 0ULL;
    return 1;
  }
  int real_size_n = (real_size_b + (int)sizeof(uint64_t) - 1) / (int)sizeof(uint64_t);
  int start_b = (int)b.size() - real_size_b;
  int partial_64_size = real_size_b - (real_size_n - 1) * (int)sizeof(uint64_t);
  byte* p = (byte*)b.data() + start_b;
  uint64_t x = 0ULL;
#ifndef BIG_ENDIAN
  memcpy((byte*)&x, p, partial_64_size);
  n[real_size_n - 1] = x;
#else
  uint64_t big_endian = 0ULL;
  reverse_bytes(partial_64_size, p, (byte*)&big_endian);
  n[real_size_n - 1] = big_endian;
#endif
  p+= partial_64_size;
  for (int i = real_size_n - 2; i >=0; i--) {
#ifndef BIG_ENDIAN
    memcpy((byte*)&x, p, sizeof(uint64_t));
    n[i] = x;
#else
    reverse_bytes((int)sizeof(uint64_t), p, (byte*)&big_endian);
    n[i] = big_endian;
#endif
    p += (int)sizeof(uint64_t);
  }
  return real_size_n;
}


key_message* make_symmetrickey(const char* alg, const char* name, int bit_size,
                               const char* purpose, const char* not_before,
                               const char* not_after, string& secret) {
  key_message* m = new(key_message);
  m->set_family_type("symmetric");
  if (alg  != nullptr)
    m->set_algorithm_type(alg);
  // key_name
  // key_size
  // purpose
  // notBefore
  // notAfter
  // secret 

  return nullptr;
}

void print_binary_blob(binary_blob_message& m) {
}

void print_encrypted_message(encrypted_message& m) {
}

void print_signature_message(signature_message& m) {
}

void print_rsa_parameters_message(rsa_parameters_message& m) {
}

void print_ecc_parameters_message(ecc_parameters_message& m) {
}

void print_rsa_public_parameters_message(rsa_public_parameters_message& m) {
}

void print_ecc_public_parameters_message(ecc_public_parameters_message& m) {
}

void print_rsa_private_parameters_message(rsa_private_parameters_message& m) {
}

void print_ecc_private_parameters_message(ecc_private_parameters_message& m) {
}

void print_curve_parameters_message(curve_parameters_message& m) {
}

void print_hmac_parameters_message(hmac_parameters_message& m) {
}

void print_key_message(key_message& m) {
}

void print_scheme_message(scheme_message& m) {
}

void print_crypto_signature_message(crypto_signature_message& m) {
}

void print_cert_name_message(cert_name_message& m) {
}

void print_cert_principal_name_message(cert_principal_name_message& m) {
}

void print_cert_rsa_parameters_message(cert_rsa_parameters_message& m) {
}

void print_cert_ecc_parameters_message(cert_ecc_parameters_message& m) {
}

void print_cert_algorithm_message(cert_algorithm_message& m) {
}

void print_cert_properties_message(cert_properties_message& m) {
}

void print_certificate_message(certificate_message& m) {
}