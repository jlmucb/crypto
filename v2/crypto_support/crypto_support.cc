// Cepyright 2020 John Manferdelli, All Rights Reserved.
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

bool time_point::encode_time(string* the_time) {
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
bool time_point::decode_time(string& encoded_time) {
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
  if (!tp.encode_time(&the_time))
    return false;
  logging_descriptor.open(log_file);
  LOG(INFO) << "Log file " << log_file << " opened " << the_time << ".\n";
  return true;
}

void close_log() {
  time_point tp;
  tp.time_now();
  string the_time;
  tp.encode_time(&the_time);
  LOG(INFO) << "Log file closed " << the_time << ".\n";
  logging_descriptor.close();
}

uint64_t read_rdtsc() {
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

uint64_t calibrate_rdtsc() {
  time_t start, end;
  uint64_t start_cycles, end_cycles;
  uint64_t cps;

  for (;;) {
    start_cycles = read_rdtsc();
    time(&start);
    sleep(2);
    end_cycles = read_rdtsc();
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

int file_util::read_file(const char* filename, int size, byte* buf) {
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

bool file_util::write_file(const char* filename, int size, byte* buf) {
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
  if (((real_size_b + (int)sizeof(uint64_t) - 1) / (int)sizeof(uint64_t)) > size_n)
    return false;
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
  for (int i = real_size_n - 2; i >= 0; i--) {
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

bool global_crypto_initialized = false;
random_source global_crypto_random_source;

int crypto_get_random_bytes(int num_bytes, byte* buf) {
  if (!global_crypto_initialized)
    return -1;
  return global_crypto_random_source.get_random_bytes(num_bytes, buf);
}

bool init_crypto() {
  if (!global_crypto_random_source.start_random_source())
    return false;
  global_crypto_initialized = true;
  return true;
}

void close_crypto() {
  if (global_crypto_initialized)
    global_crypto_random_source.close_random_source();
}


key_message* make_symmetrickey(const char* alg, const char* name, int bit_size,
                               const char* purpose, const char* not_before,
                               const char* not_after, string& secret) {
  // has_algorithm_type
  key_message* m = new(key_message);
  m->set_family_type("symmetric");
  if (alg  != nullptr)
    m->set_algorithm_type(alg);
  if (name != nullptr)
    m->set_key_name(name);
  m->set_key_size(bit_size);
  if (purpose != nullptr)
    m->set_purpose(purpose);
  if (not_before != nullptr)
    m->set_notbefore(not_before);
  if (not_after != nullptr)
    m->set_notafter(not_after);
  m->set_secret(secret);

  return m;
}

key_message* make_ecckey(const char* name, int prime_bit_size, const char* purpose,
                         const char* not_before, const char* not_after,
                         string& curve_name, string& curve_p,
                         string& curve_a, string& curve_b,
                         string& curve_base_x, string& curve_base_y,
                         string& order_base_point, string& secret,
                         string& curve_public_point_x, string& curve_public_point_y) {
  key_message* km = new(key_message);
  if (km == nullptr)
    return nullptr;
  km->set_family_type("public");
  km->set_algorithm_type("ecc");
  if (name != nullptr)
    km->set_key_name(name);
  if (purpose != nullptr)
    km->set_purpose(purpose);
  if (not_before != nullptr)
    km->set_notbefore(not_before);
  if (not_after != nullptr)
    km->set_notafter(not_after);
  km->set_key_size(prime_bit_size);

  ecc_public_parameters_message* pub = km->mutable_ecc_pub();
  curve_message* cmsg = pub->mutable_cm();
  cmsg->set_curve_name(curve_name);
  cmsg->set_curve_p((void*)curve_p.data(), (int)curve_p.size());
  cmsg->set_curve_a((void*)curve_a.data(), (int)curve_a.size());
  cmsg->set_curve_b((void*)curve_b.data(), (int)curve_b.size());
  pub->set_order_of_base_point((void*)order_base_point.data(), (int)order_base_point.size());
  point_message* bpm = pub->mutable_base_point();
  bpm->set_x((void*)curve_base_x.data(), (int)curve_base_x.size());
  bpm->set_y((void*)curve_base_y.data(), (int)curve_base_y.size());
  point_message* ppm = pub->mutable_public_point();
  ppm->set_x((void*)curve_public_point_x.data(), (int)curve_public_point_x.size());
  ppm->set_y((void*)curve_public_point_y.data(), (int)curve_public_point_y.size());

  ecc_private_parameters_message* priv = km->mutable_ecc_priv();
  priv->set_private_multiplier((void*)secret.data(), (int)secret.size());

  return km;
}

key_message* make_rsakey(const char* alg, const char* name, int bit_size,
    const char* purpose, const char* not_before, const char* not_after,
    string& mod, string& e, string& d, string& p, string& q, string& dp,
    string& dq, string& m_prime, string& p_prime, string& q_prime) {
  key_message* km = new(key_message);
  km->set_family_type("public");
  km->set_algorithm_type("rsa");
  if (name != nullptr)
    km->set_key_name(name);
  km->set_key_size(bit_size);
  if (purpose != nullptr)
    km->set_purpose(purpose);
  if (not_before != nullptr)
    km->set_notbefore(not_before);
  if (not_after != nullptr)
    km->set_notafter(not_after);

  rsa_public_parameters_message* pub = km->mutable_rsa_pub();
  pub->set_modulus((void*)mod.data(), (int)mod.size());
  pub->set_e((void*)e.data(), (int)e.size());

  rsa_private_parameters_message* priv = km->mutable_rsa_priv();
  priv->set_d((void*)d.data(), (int)d.size());
  priv->set_p((void*)p.data(), (int)p.size());
  priv->set_q((void*)q.data(), (int)q.size());
  priv->set_dq((void*)dq.data(), (int)dq.size());
  priv->set_m_prime((void*) m_prime.data(), (int)m_prime.size());
  priv->set_p_prime((void*) p_prime.data(), (int)p_prime.size());
  priv->set_q_prime((void*) q_prime.data(), (int)q_prime.size());

  return km;
}

scheme_message* make_scheme(const char* alg, const char* id_name,
      const char* mode, const char* pad, const char* purpose,
      const char* not_before, const char* not_after,
      const char* enc_alg, int size_enc_key, string& enc_key,
      const char* enc_key_name, const char* hmac_alg,
      int size_hmac_key,  string& hmac_key) {

  scheme_message* m = new(scheme_message);
  m->set_scheme_type(alg);
  m->set_scheme_instance_identifier(id_name);
  m->set_mode(mode);
  m->set_pad(pad);
  m->set_notbefore(not_before);
  m->set_notafter(not_after);
  m->set_scheme_instance_identifier(id_name);
  key_message* km = make_symmetrickey(enc_alg, enc_key_name, size_enc_key,
                               purpose, not_before, not_after, enc_key);
  m->set_allocated_encryption_key(km);
  hmac_parameters_message* hp =  new hmac_parameters_message;
  hp->set_algorithm(hmac_alg);
  hp->set_size(size_hmac_key);
  hp->set_secret(hmac_key);
  m->set_allocated_parameters(hp);
  return m;
}

void print_binary_blob(binary_blob_message& m) {
}

void print_encrypted_message(encrypted_message& m) {
}

void print_signature_message(signature_message& m) {
}

void print_rsa_public_parameters_message(rsa_public_parameters_message& m) {
}

void print_ecc_public_parameters_message(ecc_public_parameters_message& m) {
}

void print_rsa_private_parameters_message(rsa_private_parameters_message& m) {
}

void print_ecc_private_parameters_message(ecc_private_parameters_message& m) {
}

void print_hmac_parameters_message(hmac_parameters_message& m) {
  if (m.has_algorithm())
    printf("hmac algorithm: %s\n", m.algorithm().c_str());
  if (m.has_size())
    printf("hmac key size: %d\n", m.size());
  if (m.has_secret()) {
    printf("hmac secret: ");
    print_bytes((int)m.secret().size(), (byte*)m.secret().data());
  }
}

void print_key_message(key_message& m) {
  if (!m.has_family_type())
    return;
  printf("%s key\n", m.family_type().c_str());
  if (m.has_algorithm_type())
    printf("  Algorithm: %s\n", m.algorithm_type().c_str());
  if (m.has_key_name())
    printf("  Key name : %s\n", m.key_name().c_str());
  if (m.has_key_size())
    printf("  Key size : %d bits\n", m.key_size());
  if (m.has_algorithm_type())
    printf("  Purpose  : %s\n", m.purpose().c_str());
  if (m.has_notbefore())
    printf("  Not before %s\n", m.notbefore().c_str());
  if (m.has_notafter())
    printf("  Not after: %s\n", m.notafter().c_str());
  if (m.has_secret()) {
    printf("  Secret   : "); print_bytes((int)m.secret().size(),
                                (byte*)m.secret().data());
  }
  if (m.has_rsa_pub()) {
    if (m.rsa_pub().has_modulus() && (int)m.rsa_pub().modulus().size() > 0) {
      printf("  modulus: ");
      print_bytes((int)(m.rsa_pub().modulus().size()),
          (byte*)m.rsa_pub().modulus().data());
    }
    if (m.rsa_pub().has_e() && (int)m.rsa_pub().e().size() > 0) {
      printf("  e      : ");
      print_bytes((int)(m.rsa_pub().e().size()),
        (byte*)m.rsa_pub().e().data());
    }
  }
  if (m.has_rsa_priv() && (int)m.rsa_priv().d().size() > 0) {
    if (m.rsa_priv().has_d()) {
      printf("  d      : ");
      print_bytes((int)(m.rsa_priv().d().size()),
         (byte*)m.rsa_priv().d().data());
    }
    if (m.rsa_priv().has_p() && (int)m.rsa_priv().p().size() > 0) {
      printf("  p      : ");
      print_bytes((int)(m.rsa_priv().p().size()),
         (byte*)m.rsa_priv().p().data());
    }
    if (m.rsa_priv().has_q() && (int)m.rsa_priv().q().size() > 0) {
      printf("  q      : ");
      print_bytes((int)(m.rsa_priv().q().size()),
        (byte*)m.rsa_priv().q().data());
    }
    if (m.rsa_priv().has_m_prime() && (int)m.rsa_priv().m_prime().size() > 0) {
      printf("  m_prime: ");
      print_bytes((int)(m.rsa_priv().m_prime().size()),
        (byte*)m.rsa_priv().m_prime().data());
    }
    if (m.rsa_priv().has_p_prime() && (int)m.rsa_priv().p_prime().size() > 0) {
      printf("  p_prime: ");
      print_bytes((int)(m.rsa_priv().p_prime().size()),
        (byte*)m.rsa_priv().p_prime().data());
    }
    if (m.rsa_priv().has_q_prime() && (int)m.rsa_priv().q_prime().size() > 0) {
      printf("  q_prime: ");
      print_bytes((int)(m.rsa_priv().q_prime().size() / NBITSINBYTE),
        (byte*)m.rsa_priv().q_prime().data());
    }
  }
  if (m.has_ecc_pub()) {
    ecc_public_parameters_message* pub = m.mutable_ecc_pub();
    if (pub->has_cm()) {
      curve_message* cmsg= pub->mutable_cm();
      if (cmsg->has_curve_name())  
        printf("  curve name       : %s\n", cmsg->curve_name().c_str());
      if (cmsg->has_curve_p())   {
        printf("  curve p          : ");
        print_bytes((int)cmsg->curve_p().size(), (byte*)cmsg->curve_p().data());
      }
      if (cmsg->has_curve_a())   {
        printf("  curve a          : ");
        print_bytes((int)cmsg->curve_a().size(), (byte*)cmsg->curve_a().data());
      }
      if (cmsg->has_curve_b())   {
        printf("  curve b          : ");
        print_bytes((int)cmsg->curve_b().size(), (byte*)cmsg->curve_b().data());
      }
    }
    if (pub->has_base_point()) {
        point_message* pt= pub->mutable_base_point();
        if (pt->has_x()) {
          printf("  curve base x     : ");
          print_bytes((int)pt->x().size(), (byte*)pt->x().data());
        }
        if (pt->has_y()) {
          printf("  curve base y     : ");
          print_bytes((int)pt->y().size(), (byte*)pt->y().data());
        }
    }
    if (pub->has_public_point()) {
        point_message* pt= pub->mutable_public_point();
        if (pt->has_x()) {
          printf("  curve public x   : ");
          print_bytes((int)pt->x().size(), (byte*)pt->x().data());
        }
        if (pt->has_y()) {
          printf("  curve public y   : ");
          print_bytes((int)pt->y().size(), (byte*)pt->y().data());
        }
    }
    if (pub->has_order_of_base_point()) {
        printf("  order of base    : ");
        print_bytes((int)pub->order_of_base_point().size(), (byte*)pub->order_of_base_point().data());
    }

  }
  if (m.has_ecc_priv() && (int)m.ecc_priv().private_multiplier().size() > 0) {
      printf("  private multiplier: ");
      print_bytes((int)m.ecc_priv().private_multiplier().size(), (byte*)m.ecc_priv().private_multiplier().data());
  }
}

void print_scheme_message(scheme_message& m) {
  printf("Scheme: ");
  if (m.has_scheme_type()) {
    printf("scheme: %s\n", m.scheme_type().c_str());
  }
  if (m.has_scheme_instance_identifier()) {
    printf("scheme identifier: %s\n", m.scheme_instance_identifier().c_str());
  }
  if (m.has_mode()) {
    printf("mode: %s\n", m.mode().c_str());
  }
  if (m.has_pad()) {
    printf("pad: %s\n", m.pad().c_str());
  }
  if (m.has_notbefore()) {
    printf("not before: %s\n", m.notbefore().c_str());
  }
  if (m.has_notafter()) {
    printf("not after: %s\n", m.notafter().c_str());
  }
  if (m.has_encryption_key()) {
    key_message* km = m.mutable_encryption_key();
    print_key_message(*km);
  }
  if (m.has_parameters()) {
    hmac_parameters_message* hp = m.mutable_parameters();
    print_hmac_parameters_message(*hp);
  }
}

void print_crypto_signature_message(crypto_signature_message& m) {
}

void print_certificate_name_message(certificate_name_message& m) {
  if (m.has_name_type()) 
    printf("  Name type: %s, ", m.name_type().c_str());
  if (m.has_name_value()) 
    printf("  name     : %s\n", m.name_value().c_str());
}

void print_algorithm_message(certificate_algorithm_message& am) {
  printf("  Algorithm name: %s\n", am.algorithm_name().c_str());
  if (strcmp(am.algorithm_name().c_str(), "rsa") == 0) {
    rsa_public_parameters_message* rm = am.mutable_rsa_params();
    print_rsa_public_parameters_message(*rm);
  } else if (strcmp(am.algorithm_name().c_str(), "ecc") == 0) {
      ecc_public_parameters_message* em = am.mutable_ecc_params();
      print_ecc_public_parameters_message(*em);
  } else {
    printf("  unsupported cert algorithm\n");
  }
}

void print_certificate_body(certificate_body_message& cbm) {
  if (cbm.has_version()) {
    printf("  Version: %s\n", cbm.version().c_str());
  }
  if (cbm.has_subject()) {
    certificate_name_message* sn = cbm.mutable_subject();
    printf("  Subject       : \n");
    print_certificate_name_message(*sn);
  }
  if (cbm.has_subject_key()) {
    printf("  Subject key : \n");
    certificate_algorithm_message* sk = cbm.mutable_subject_key();
    print_algorithm_message(*sk);
  }
  if (cbm.has_purpose()) {
    printf(" Purpose      : %s\n", cbm.purpose().c_str());
  }
  if (cbm.has_not_before()) {
    printf(" Not before   : %s\n", cbm.not_before().c_str());
  }
  if (cbm.has_not_after()) {
    printf(" Not after    : %s\n", cbm.not_after().c_str());
  }
  if (cbm.has_revocation_address()) {
    printf(" Revocation   : %s\n", cbm.revocation_address().c_str());
  }
  if (cbm.has_date_signed()) {
    printf(" Date signed  : %s\n", cbm.date_signed().c_str());
  }
}

void print_certificate_message(certificate_message& m) {
  if (m.has_info()) {
    certificate_body_message* cbm = m.mutable_info();
    print_certificate_body(*cbm);
  }
  if (m.has_issuer()) {
    certificate_name_message* in = m.mutable_issuer();
    printf("  Issuer        : \n");
    print_certificate_name_message(*in);
  }
  if (m.has_signing_key()) {
    certificate_algorithm_message* ik = m.mutable_signing_key();
    print_algorithm_message(*ik);
  }
  printf("  Signature     : ");
  print_bytes((int)m.signature().size(), (byte*)m.signature().data());
}
