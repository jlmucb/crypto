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
// File: entropy_collection.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "probability_support.h"
#include "hash_df.h"
#include "entropy_collection.h"

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

entropy_collection::entropy_collection() {
  initialized_= false;
  reseed_ctr_ = 0;
  current_entropy_in_pool_= 0;
  num_ent_bits_required_ = 0;
  current_size_pool_ = 0;
  pool_size_ = 0;
  hash_byte_output_size_ = sha256::DIGESTBYTESIZE;
  memset(pool_, 0, MAXPOOL_SIZE);
  reseed_interval_ = 100;
  seed_len_bits_ = 440;  // we're using sha256
  seed_len_bytes_ = seed_len_bits_ / NBITSINBYTE;;
}

entropy_collection::~entropy_collection() {
  initialized_= false;
  reseed_ctr_ = 0;
  current_entropy_in_pool_= 0;
  num_ent_bits_required_ = 0;
  current_size_pool_ = 0;
  pool_size_ = 0;
  memset(pool_, 0, MAXPOOL_SIZE);
  memset(C_, 0, 64);
  memset(V_, 0, 64);
}

void entropy_collection::set_policy(int n_ent, int byte_pool_size, int reseed_interval) {
  num_ent_bits_required_ = n_ent;
  if (byte_pool_size > MAXPOOL_SIZE * NBITSINBYTE)
    pool_size_ = MAXPOOL_SIZE;
  else
    pool_size_ = byte_pool_size;
  reseed_interval_ = reseed_interval;
}

// nw = width (256 for our hash)
// n_in input to conditioner
// n_out output
// p_h = 2^(-ent) p_l= (1-p_h)/(2^current_ent - 1)
double conditioned_entropy_estimate(double h_in, int nw, int n_in, int n_out) {
  return h_in;
}

void entropy_collection::add_entropy(int size_bytes, byte* bits, double ent) {
  if ((size_bytes + current_size_pool_) <= MAXPOOL_SIZE) {
    memcpy(&pool_[current_size_pool_], bits, size_bytes);
    current_size_pool_ += size_bytes;
    current_entropy_in_pool_ += ent;
  }
#if 0
conditioned_entropy_estimate(ent, NBITSINBYTE * sha256::DIGESTBYTESIZE,
         NBITSINBYTE * size_bytes, pool_size_);
#endif
}

double entropy_collection::entropy_estimate() {
  return current_entropy_in_pool_;
}

bool entropy_collection::init(int size_nonce, byte* nonce, int size_personalization, byte* personalization) {
  reseed_ctr_ = 0;
  if (num_ent_bits_required_ > current_entropy_in_pool_)
    return false;
  int seed_material_size = current_size_pool_ + size_nonce + size_personalization;
  byte seed_material[seed_material_size];
  memset(seed_material, 0, seed_material_size);
  memcpy(seed_material, pool_, current_size_pool_);
#if 0
  printf("init, seed material: "); print_bytes(seed_material_size, seed_material);printf("\n");
#endif
  hash_df(seed_material_size, seed_material, seed_len_bits_, V_);
  memset(seed_material, 0, seed_material_size);
  memcpy(&seed_material[1], V_, seed_len_bytes_);
  hash_df(seed_len_bytes_ + 1, seed_material, seed_len_bits_, C_);
  current_entropy_in_pool_= 0;
  current_size_pool_ = 0;
  initialized_= true;
  reseed_ctr_ = 1;
#if 0
  printf("V initial: ");print_bytes(55, V_); printf("\n");
  printf("C initial: ");print_bytes(55, C_); printf("\n");
#endif
  return initialized_;
}

bool entropy_collection::reseed() {
  reseed_ctr_ = 0;
  if (num_ent_bits_required_ > current_entropy_in_pool_)
    return false;
  int seed_material_size = 1 + current_size_pool_ + seed_len_bytes_;
  byte seed_material[seed_material_size];
  memset(seed_material, 0, seed_material_size);
  seed_material[0] = 0x01;
  memcpy(&seed_material[1], V_, seed_len_bytes_);
  memcpy(&seed_material[1 + seed_len_bytes_], pool_, current_size_pool_);
#if 0
  printf("init, seed material: "); print_bytes(seed_material_size, seed_material);printf("\n");
#endif
  hash_df(seed_material_size, seed_material, seed_len_bits_, V_);
  memset(seed_material, 0, seed_material_size);
  memcpy(&seed_material[1], V_, seed_len_bytes_);
  hash_df(seed_len_bytes_ + 1, seed_material, seed_len_bits_, C_);
  current_entropy_in_pool_= 0;
  current_size_pool_ = 0;
  initialized_= true;
  reseed_ctr_ = 1;
#if 0
  printf("reseed V initial: ");print_bytes(55, V_); printf("\n");
  printf("reseed C initial: ");print_bytes(55, C_); printf("\n");
#endif
  return initialized_;
}

bool entropy_collection::health_check() {
  return true;
}

void entropy_collection::hash_gen(int num_requested_bits, byte* out) {
  int size_output_bytes = (num_requested_bits + NBITSINBYTE - 1) / NBITSINBYTE;
  int m = size_output_bytes / hash_byte_output_size_;
  byte data[seed_len_bytes_ + 1];  // to fill to uint64_t boundary
  memset(data, 0, seed_len_bytes_ + 1);
  memcpy(data, V_, seed_len_bytes_);
  int bytes_so_far = 0;
  byte extra_out[hash_byte_output_size_];
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

bool entropy_collection::generate(int num_bits_needed, byte* out, int size_add_in_bits,
            byte* add_in_bits) {
  sha256 hash_obj;

  if (reseed_ctr_ > reseed_interval_)
    reseed();
  if (current_entropy_in_pool_ < num_ent_bits_required_)
    return false;
  int add_in_byte_size = (size_add_in_bits + NBITSINBYTE - 1) / NBITSINBYTE;

  if (size_add_in_bits > 0) {
    // w = Hash(0x02 || V_||add_in_bits)
    byte w[hash_byte_output_size_];
    memset(w, 0, hash_byte_output_size_);
    byte two = 0x02;
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
    reverse_bytes(55, (byte*)t, V_);
    reverse_bytes_in_place(32, w);
  }

  hash_gen(num_bits_needed, out);

  // H = Hash(0x03||V_)
  byte H[hash_byte_output_size_];
  memset(H, 0, hash_byte_output_size_);
  byte three = 0x03;
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
