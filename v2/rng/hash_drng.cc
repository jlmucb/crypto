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
// File: hash_drng.cc

#include <stdio.h>
#include "crypto_support.h"
#include "probability_support.h"
#include "hash_df.h"
#include "hash_drng.h"

// Note:  Mixers assume big endian so reverse bytes should
// be invoked before and after any call to the addition stuff.
// size_n1 >= size_n2
void big_add(int size_n1, uint64_t* n1, int size_n2, uint64_t* n2,
             int size_out, uint64_t* out) {

  zero_uint32_array(2 * size_out, (uint32_t*) out);
  int usize1 = 2 * size_n1;
  int usize2 = 2 * size_n2;
  uint32_t* p1= (uint32_t*) n1;
  uint32_t* p2= (uint32_t*) n2;
  uint32_t* p3= (uint32_t*) out;
  uint32_t carry = 0ULL;
  uint32_t x, y;
  uint64_t t;

  for (int i = 0; i < 2 * size_out; i++) {
    if (i < usize2)
      x = p2[i];
    else
      x = 0;
    if (i < usize1)
      y = p1[i];
    else
      y = 0;
  t = (uint64_t) x + (uint64_t)y + (uint64_t) carry;
  p3[i] = t&0xffffffff;
  carry = t >> 32;
  }
#if 0
  printf("n1: "); print_uint64_array(size_n1, n1); printf("\n");
  printf("n2: "); print_uint64_array(size_n2, n2); printf("\n");
  printf("out: "); print_uint64_array(size_out, out); printf("\n");
  printf("\n");
#endif
}

void big_add_one(int size_n, uint64_t* n) {
  uint64_t carry = 1;

#if 0
  printf("big_add_one, in : "); print_uint64_array(size_n, n); printf("\n");
#endif
  for (int i = 0; i < size_n; i++) {
    if (carry != 0) {
      if (n[i] < 0xffffffffffffffffULL) {
        n[i] = n[i] + 1ULL;
        carry = 0;
      } else {
        n[i] = 0ULL;
      }
    } else {
      n[i] = n[i];
    }
  }

#if 0
  printf("big_add_one, out: "); print_uint64_array(size_n, n); printf("\n");
#endif
}

hash_drng::hash_drng() {
  initialized_= false;
  reseed_ctr_ = 0;
  hash_byte_output_size_ = sha256::DIGESTBYTESIZE;
  seed_len_bits_ = 440;  // we're using sha256
  seed_len_bytes_ = seed_len_bits_ / NBITSINBYTE;;
  current_entropy_ = 0;
}

hash_drng::~hash_drng() {
  initialized_= false;
  reseed_ctr_ = 0;
  current_entropy_ = 0;
  memset(C_, 0, 64);
  memset(V_, 0, 64);
}

double hash_drng::current_entropy() {
  return current_entropy_;
}

bool hash_drng::init(int size_nonce, byte_t* nonce, int size_personalization,
      byte_t* personalization, int entropy_width, byte_t* material, double ent) {
  reseed_ctr_ = 0;
  int seed_material_size = entropy_width + size_nonce + size_personalization;

  byte_t seed_material[seed_material_size];
  memset(seed_material, 0, seed_material_size);
  memcpy(seed_material, material, entropy_width);
#if 0
  printf("init, seed material: "); print_bytes(seed_material_size, seed_material);printf("\n");
#endif
  hash_df(seed_material_size, seed_material, seed_len_bits_, V_);
  memset(seed_material, 0, seed_material_size);
  memcpy(&seed_material[1], V_, seed_len_bytes_);
  hash_df(seed_len_bytes_ + 1, seed_material, seed_len_bits_, C_);
  current_entropy_ = ent;
  reseed_ctr_ = 1;
#if 0
  printf("V initial: ");print_bytes(55, V_); printf("\n");
  printf("C initial: ");print_bytes(55, C_); printf("\n");
#endif
  initialized_= true;
  return initialized_;
}

void hash_drng::hash_gen(int num_requested_bits, byte_t* out) {
  int size_output_bytes = (num_requested_bits + NBITSINBYTE - 1) / NBITSINBYTE;
  int m = size_output_bytes / hash_byte_output_size_;
  byte_t data[seed_len_bytes_ + 1];  // to fill to uint64_t boundary
  memset(data, 0, seed_len_bytes_ + 1);
  memcpy(data, V_, seed_len_bytes_);
  int bytes_so_far = 0;
  byte_t extra_out[hash_byte_output_size_];
  memset(extra_out, 0, hash_byte_output_size_);
  sha256 hash_obj;

  for (int i = 0; i < m; i++) {
    hash_obj.init();
    hash_obj.add_to_hash(seed_len_bytes_, data);
    hash_obj.finalize();
    hash_obj.get_digest(hash_byte_output_size_, &out[bytes_so_far]);
    bytes_so_far += hash_byte_output_size_;
    reverse_bytes_in_place(55, data);
    big_add_one(7, (uint64_t*)data);
    reverse_bytes_in_place(55, data);
  }
  // partial block --- avoid overflow
  if (bytes_so_far < size_output_bytes) {
    hash_obj.init();
    hash_obj.add_to_hash(seed_len_bytes_, data);
    hash_obj.finalize();
    hash_obj.get_digest(hash_byte_output_size_, extra_out);
    int n = 0;
    while (size_output_bytes > bytes_so_far) {
      out[bytes_so_far] = extra_out[n++];
      bytes_so_far++;
      }
  }
}

bool hash_drng::generate_random_bits(int num_bits_needed, byte_t* out, int size_add_in_bits,
            byte_t* add_in_bits) {
  sha256 hash_obj;

  int add_in_byte_size = (size_add_in_bits + NBITSINBYTE - 1) / NBITSINBYTE;

  if (size_add_in_bits > 0) {
    // w = Hash(0x02 || V_||add_in_bits)
    byte_t w[hash_byte_output_size_];
    memset(w, 0, hash_byte_output_size_);
    byte_t two = 0x02;
    hash_obj.init();
    hash_obj.add_to_hash(1, &two);
    hash_obj.add_to_hash(seed_len_bytes_, V_);
    hash_obj.add_to_hash(add_in_byte_size, add_in_bits);
    hash_obj.finalize();
    hash_obj.get_digest(hash_byte_output_size_, w);

    // V+= w mod 2^seedlen
    reverse_bytes_in_place(55, V_);
    reverse_bytes_in_place(32, w);
    int size_v = (seed_len_bytes_ + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    uint64_t t[size_v];
    big_add(size_v, (uint64_t*) V_, 4, (uint64_t*) w, size_v, t);
    reverse_bytes(55, (byte_t*)t, V_);
    reverse_bytes_in_place(32, w);
  }

  hash_gen(num_bits_needed, out);

  // H = Hash(0x03||V_)
  byte_t H[hash_byte_output_size_];
  memset(H, 0, hash_byte_output_size_);
  byte_t three = 0x03;
  hash_obj.init();
  hash_obj.add_to_hash(1, &three);
  hash_obj.add_to_hash(seed_len_bytes_, V_);
  hash_obj.finalize();
  hash_obj.get_digest(hash_byte_output_size_, H);

#if 0
  printf("H: ");print_bytes(32, H);printf("\n");
#endif

  // V = V + H + C + reseed_ctr
  int size_t = (seed_len_bytes_ + sizeof(uint64_t) - 1) / sizeof(uint64_t) + 1;
  uint64_t t0[size_t];
  uint64_t t1[size_t];
  uint64_t t2[size_t];
  zero_uint32_array(2*size_t, (uint32_t*) t1);
  zero_uint32_array(2*size_t, (uint32_t*) t2);
  reverse_bytes_in_place(55, V_);
  reverse_bytes_in_place(55, C_);
  reverse_bytes_in_place(32, H);
  big_add(size_t, (uint64_t*) V_, size_t, (uint64_t*) C_, size_t, t1);
  big_add(size_t, t1, 4, (uint64_t*)H, size_t, t2);
  zero_uint32_array(2*size_t, (uint32_t*) t1);
  zero_uint32_array(2*size_t, (uint32_t*) V_);
  t1 [0] = reseed_ctr_;
  big_add(size_t, t2, size_t, t1, size_t, (uint64_t*) V_);
  reverse_bytes_in_place(55, V_);
  reverse_bytes_in_place(55, C_);
  reverse_bytes_in_place(32, H);
  for(int i= 55; i < 64; i++) V_[i] = 0;
  reseed_ctr_++;
#if 0
  printf("new V: ");print_bytes(55, V_); printf("\n");
  printf("new C: ");print_bytes(55, C_); printf("\n");
#endif
  return true;
}
