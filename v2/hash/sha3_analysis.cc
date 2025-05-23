//
// Copyright 2021 John Manferdelli, All Rights Reserved.
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
// File: sha3_analysis.cc

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef byte_t
typedef uint8_t byte_t;
#endif
const int lane_exp = 6;

inline int lane_size(int exp) {
  return 1 << exp;
}

inline int state_size() {
  return 25 * lane_size(lane_exp);
}

inline int capacity_size(int n) {
  return 2 * n;
}

inline int num_rounds(int b) {
  return 12 + 2 * lane_exp;
}

int index(int size_lane, int x, int y, int z) {     // row, col, lane
  return size_lane * (5 * y + x) + z;
}

void print_row(int size_lane, int y, int z, byte_t* s) {
  printf("row %d %d: ", y, z);
  for (int x= 0; x < 5; x++)
    printf("%1x", s[index(size_lane, x, y, z)]);
  printf("\n");
}

void print_col(int size_lane, int x, int z, byte_t* s) {
  printf("column %d %d: ", x, z);
  for (int y= 0; y < 5; y++)
    printf("%1x", s[index(size_lane, x, y, z)]);
  printf("\n");
}

void print_lane (int size_lane, int x, int y, byte_t* s) {
  printf("lane %d %d: ", x, y);
  for (int z= 0; z < size_lane; z++)
    printf("%1x", s[index(size_lane, x, y, z)]);
  printf("\n");
}

bool bytes_to_bits(int num_bytes, byte_t* in, byte_t* out) {
  for (int i = 0; i < num_bytes; i++) {
    for (int j = 0; j < 8; j++) {
      out[8 * i + j] = (in[i] >> (7 - j)) & 0x1;
    }
  }
  return true;
}

void index_pair_transform(int x_in, int y_in, int* x_out, int* y_out) {
  int a = y_in;
  int b = (2 * x_in + 3 * y_in) % 5;
  *x_out = a;
  *y_out = b;
}

//#define INTERMEDIATETHETA
byte_t column_parities(int size_lane, byte_t* in_state, int x, int z) {
  byte parity = 0;

  int x1 = (x + 4) % 5;
  int z1 = z;
  int x2 = (x + 1) % 5;
  int z2 = (z + 1) % 5;
  for (int y = 0; y < 5; y++) {
    parity ^= (in_state[index(size_lane, x1, y, z1)] ^ in_state[index(size_lane, x2, y, z2)]);
  }
#ifdef INTERMEDIATETHETA
  print_col(size_lane, x1, z1, in_state);
  print_col(size_lane, x2, z2, in_state);
  printf("parity: %d\n", parity);
#endif
  return parity;
}


// add parity of two columns to a column
void theta_f(int size_lane, byte_t* in_state, byte_t* out_state) {
  for (int x = 0; x < 5; x++) {
    for (int z = 0; z < size_lane; z++) {
#ifdef INTERMEDIATETHETA
      printf("before, ");
      print_col(size_lane, x, z, in_state);
#endif
      byte_t parity = column_parities(size_lane, in_state, x, z);
      for (int y = 0; y < 5; y++) {
        out_state[index(size_lane, x, y, z)] =  in_state[index(size_lane, x, y, z)] ^ parity;
      }
#ifdef INTERMEDIATETHETA
      printf("after, ");
      print_col(size_lane, x, z, out_state);
#endif
    }
  }
}

void mat_mult(int a11, int a12, int a21, int a22,
              int b11, int b12, int b21, int b22,
              int* c11, int* c12, int* c21, int* c22) {
  *c11 = (a11*b11 + a12*b21) % 5;
  *c12 = (a11*b12 + a12*b22) % 5;
  *c21 = (a21*b11 + a22*b21) % 5;
  *c22 = (a21*b12 + a22*b22) % 5;
}

//#define INTERMEDIATERHO
// rotate bits in lane by T(x,y)
void rho_f(int size_lane, byte_t* in_state, byte_t* out_state) {
  int x1, y1;
  int a11 = 1; int a12 = 0;
  int a21 = 0; int a22 = 1;
  int c11, c12, c21, c22;
  int k;

  for (int t = 0; t <= 24; t++) {
    x1 = a11; y1= a21;
#ifdef INTERMEDIATERHO
    printf("rho, before, t: %d, a11: %d, a12: %d, a21: %d, a22: %d, x1:%d, y1: %d\n",
           t, a11, a12, a21, a22, x1, y1);
    print_lane (size_lane, x1, y1, in_state);
#endif
    for (int z = 0; z < size_lane; z++) {
      if (t == 24) {
        x1 = 0;
        y1 = 0;
        k = z % size_lane;
      } else {
        k = (size_lane + z - ((t + 1)*(t + 2)) / 2) % size_lane;
      }
      out_state[index(size_lane, x1, y1, z)] = in_state[index(size_lane, x1, y1, k)];
#ifdef INTERMEDIATERHO
      printf("\tk: %d, z: %d\n", k, z);
#endif
    }
#ifdef INTERMEDIATERHO
    printf("after, ");
    print_lane (size_lane, x1, y1, out_state);
#endif
    mat_mult(a11, a12, a21, a22, 0, 1, 2, 3, &c11, &c12, &c21, &c22);
    a11 = c11; a12 = c12; a21 = c21; a22 = c22;
  }
}

// #define INTERMEDIATEPI
// reorder lanes
void pi_f(int size_lane, byte_t* in_state, byte_t* out_state) {
  int x1, y1;
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      index_pair_transform(x, y, &x1, &y1);
#ifdef INTERMEDIATEPI
    printf("x: %d, y: %d, x1: %d, y1: %d\n", x,y,x1,y1);
#endif
      for (int z = 0; z < size_lane; z++) {
        out_state[index(size_lane, x1, y1, z)] =  in_state[index(size_lane, x1, y1, z)];
      }
    }
  }
}

// #define INTERMEDIATECHI
// non-linear transform of rows
void chi_f(int size_lane, byte_t* in_state, byte_t* out_state) {
  byte_t r;

  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < size_lane; z++) {
        r = (in_state[index(size_lane, (x + 1) % 5, y, z)] ^ 1) & in_state[index(size_lane, (x + 2) % 5, y, z)];
        out_state[index(size_lane, x, y, z)] =  in_state[index(size_lane, x, y, z)] ^ r;
#ifdef INTERMEDIATECHI
        printf("x: %d, y: %d, z: %d, x + 1: %d, x + 2: %d, a1: %d, a2: %d, r: %d, in: %d, out: %d\n",
           x, y, z, (x + 1) % 5, (x + 2) %5,
           in_state[index(size_lane, (x + 1) % 5, y, z)], in_state[index(size_lane, (x + 2) % 5, y, z)],
           r, in_state[index(size_lane, x, y, z)], out_state[index(size_lane, x, y, z)]);
#endif
      }
    }
  }
}

byte_t local_round_constants[24] = {
  0x01, 0x1a, 0x5e, 0x70, 0x1f, 0x21, 0x79, 0x55,
  0x0e, 0x0c, 0x35, 0x26, 0x3f, 0x4f, 0x5d, 0x53,
  0x52, 0x48, 0x16, 0x66, 0x79, 0x58, 0x21, 0x74
};
int positions[7] = {0, 1, 5, 7, 15, 31, 63};

// #define INTERMEDIATEIOTA
// add round constants
void iota_f(int rnd, int size_lane, byte_t* in_state) {
  for (int j = 0; j < 7; j++) {
    if (((((byte_t)1)<<j) & local_round_constants[rnd]) != 0) {
#ifdef INTERMEDIATEIOTA
    printf("rnd: %d, (0, 0, %d) ^= 1\n",  rnd, positions[j]);
#endif
      in_state[index(size_lane, 0, 0, positions[j])] ^= 1;
    }
  }
}

void init_state(int size_lane, byte_t* state) {
  for (int i = 0; i < (state_size() - 1); i++)
    state[i] = 0;
}

void print_bytes(int n, byte_t* in) {
  int i;

  for(i = 0; i < n; i++) {
    printf("%02x",in[i]);
    if ((i%32)== 31)
      printf("\n");
  }
  if ((i%32) != 0)
    printf("\n");
}

void print_state(int size_lane, byte_t* state_in) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      printf("(%d, %d): ", x, y);
      for (int z = 0; z < size_lane; z++) {
        printf("%1d", state_in[index(size_lane, x, y, z)]); 
      }
      printf("\n");
    }
  }
}

//#define INTERMEDIATEF
void keccak_f(int size_lane, byte_t* state_in, byte_t* state_out) {
  byte_t state1[1600];
  byte_t state2[1600];

  memcpy(state2, state_in, 1600);
#ifdef INTERMEDIATEF
  printf("initial state:\n");
  print_state(size_lane, state_in);
#endif
  for (int round = 0;  round < 24; round++) {
#ifdef INTERMEDIATEF
    printf("\nround %d\n", round);
#endif
    memset(state1, 0, 1600);
    theta_f(size_lane, state2, state1);
#ifdef INTERMEDIATEF
    printf("after theta:\n");
    print_state(size_lane, state1);
#endif
    memset(state2, 0, 1600);
    rho_f(size_lane, state1, state2);
#ifdef INTERMEDIATEF
    printf("after rho:\n");
    print_state(size_lane, state2);
#endif
    memset(state1, 0, 1600);
    pi_f(size_lane, state2, state1);
#ifdef INTERMEDIATEF
    printf("after pi:\n");
    print_state(size_lane, state1);
#endif
    memset(state2, 0, 1600);
    chi_f(size_lane, state1, state2);
#ifdef INTERMEDIATEF
    printf("after chi:\n");
    print_state(size_lane, state2);
#endif
    iota_f(round, size_lane, state2);
#ifdef INTERMEDIATEF
    printf("after iota:\n");
    print_state(size_lane, state2);
#endif
  }
  memcpy(state_out, state2, 1600);
#ifdef INTERMEDIATEF
  printf("final state:\n");
  print_state(size_lane, state_out);
#endif
}

bool pad(int r, int size_in, int* pad_size, byte_t* pad_buf) {
  int num_in_last_block = size_in % r;
  int num_left;
  if (num_in_last_block == 0)
    num_left = r;
  else
    num_left = r - num_in_last_block;
    
  if (num_left > *pad_size)
    return false;
  *pad_size = num_left;
  for (int i = 0; i < num_left; i++)
    pad_buf[i] = 0;
  pad_buf[0] = 1;
  pad_buf[num_left - 1] = 1;
  return true;
}

#define INTERMEDIATEBLOCK
bool sponge(int b, int r, int size_lane, int num_blocks_with_pad, byte_t* bit_blocks,
            int num_bits_out, byte_t* bits_out) {
  byte_t state_in[1600];
  byte_t state_out[1600];
  memset(state_in, 0, 1600);
  memset(state_out, 0, 1600);

  memset(bits_out, 0, num_bits_out);

  int bn = 0;
  for (bn = 0; bn < num_blocks_with_pad; bn++) {
#ifdef INTERMEDIATEBLOCK
    printf("Block %d: \n", bn);
#endif
    // xor block into state
    for( int j = 0; j < r; j++) {
      state_in[j] ^= bit_blocks[bn * r + j];
    }
#ifdef INTERMEDIATEBLOCK
    printf("in  :\n");
    print_state(size_lane, state_in);
#endif
    // xor block padded with 0
    keccak_f(size_lane, state_in, state_out);
#ifdef INTERMEDIATEBLOCK
    printf("out :\n");
    print_state(size_lane, state_out);
    printf("\n");
#endif
  }
  if (num_bits_out > r) {
    printf("output larger than width\n");
    return false;
  }
  // output num_out bytes
  for (int i = 0; i < num_bits_out; i++)
    bits_out[i] = state_out[i];
  return true;
}

const int num_bytes_to_hash = 16;
byte_t to_hash[num_bytes_to_hash] = {
  0x01, 0x03, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08,
  0xa1, 0xb3, 0xc2, 0xd4, 0xe5, 0xf6, 0x97, 0xa8,
};

int main(int an, char** av) {
  int b = state_size();
  int c = 576;
  int r = state_size() - c;

  printf("Keccak b= %d, c= %d, r= %d\n", b, c, r);

  byte_t bit_blocks[r];
  int num_bits_out = 256;
  byte_t bits_out[num_bits_out];
  memset(bit_blocks, 0, r);
  memset(bits_out, 0, 256);

  printf("to hash: ");
  print_bytes(num_bytes_to_hash, to_hash);
  if (!bytes_to_bits(num_bytes_to_hash, to_hash, bit_blocks)) {
    printf("Cant convert to bits\n");
    return 1;
  }
  printf("to hash as bits: ");
  for(int i = 0; i < 8 * num_bytes_to_hash; i++) {
    printf("%1x", bit_blocks[i]);
  }
  printf("\n");

  int size_lane = lane_size(lane_exp);
  int num_blocks_with_pad = 1;

  // pad
  int pad_size = 1024;
  if (!pad(r, 8 * num_bytes_to_hash, &pad_size, &bit_blocks[8 * num_bytes_to_hash])) {
    printf("pad failed\n");
    return 1;
  }
  printf("pad size = %d, total: %d\n", pad_size, 8 * num_bytes_to_hash + pad_size);
  if ((8 * num_bytes_to_hash + pad_size) != r) {
    printf("bad padded block size\n");
    return 1;
  }
  printf("padded bits to hash: ");
  for(int i = 0; i < r; i++) {
    printf("%1x", bit_blocks[i]);
  }
  printf("\n");

  if (!sponge(b, r, size_lane, num_blocks_with_pad, bit_blocks, num_bits_out, bits_out)) {
    printf("sponge failed\n");
    return 1;
  }

  return 0;
}


#if 0
uint64_t RoundConstants[24] = {
    (uint64_t)0x0000000000000001ULL, (uint64_t)0x0000000000008082ULL,
    (uint64_t)0x800000000000808aULL, (uint64_t)0x8000000080008000ULL,
    (uint64_t)0x000000000000808bULL, (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008009ULL,
    (uint64_t)0x000000000000008aULL, (uint64_t)0x0000000000000088ULL,
    (uint64_t)0x0000000080008009ULL, (uint64_t)0x000000008000000aULL,
    (uint64_t)0x000000008000808bULL, (uint64_t)0x800000000000008bULL,
    (uint64_t)0x8000000000008089ULL, (uint64_t)0x8000000000008003ULL,
    (uint64_t)0x8000000000008002ULL, (uint64_t)0x8000000000000080ULL,
    (uint64_t)0x000000000000800aULL, (uint64_t)0x800000008000000aULL,
    (uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008080ULL,
    (uint64_t)0x0000000080000001ULL, (uint64_t)0x8000000080008008ULL};

void print_round_constants() {
  uint64_t  a;
  byte b = 0;
  int positions[7] = {0, 1, 3, 7, 15, 31, 63};
  byte local_round_constants[24];

  for (int i = 0; i < 24; i++) {
    a = RoundConstants[i];
    printf("round %02d: ", i);
    for (int j = 0; j < 64; j++) {
      if (a&1ULL)
        printf("%d ", j);
      a >>= 1ULL;
    }
    printf("\n");
    b = 0; 
    a = RoundConstants[i];
    for (int j = 0; j < 7; j++) {
      if (((((uint64_t) 1) << positions[j]) & a) != 0) {
        b |= ((byte)1) << j;
      }
    }
    local_round_constants[i] = b;
    printf("rk_word[%d] = 0x%02x\n", i, b);
  }

  printf("\nlocal_round_constants[24] = {");
  for (int i = 0; i < 24; i++) {
    printf("%02x, ", local_round_constants[i]);
  }
  printf("\n}\n");
}
#endif
