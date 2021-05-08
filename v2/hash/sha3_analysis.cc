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

typedef uint8_t byte;
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

void print_row(int size_lane, int y, int z, byte* s) {
  printf("row %d %d: ", y, z);
  for (int x= 0; x < 5; x++)
    printf("%1x", s[index(size_lane, x, y, z)]);
  printf("\n");
}

void print_col(int size_lane, int x, int z, byte* s) {
  printf("column %d %d: ", x, z);
  for (int y= 0; y < 5; y++)
    printf("%1x", s[index(size_lane, x, y, z)]);
  printf("\n");
}

void print_lane (int size_lane, int x, int y, byte* s) {
  printf("lane %d %d: ", x, y);
  for (int z= 0; z < size_lane; z++)
    printf("%1x", s[index(size_lane, x, y, z)]);
  printf("\n");
}

bool bytes_to_bits(int num_bytes, byte* in, byte* out) {
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

byte column_parities(int size_lane, byte* in_state, int x, int z) {
  byte parity = 0;

  int x1 = (x + 4) % 5;
  int z1 = z;
  int x2 = (x + 1) % 5;
  int z2 = (z + 1) % 5;
  for (int y = 0; y < 4; y++) {
    parity ^= in_state[index(size_lane, x1, y, z1)] ^ in_state[index(size_lane, x2, y, z2)];
  }
  return parity;
}


// add parity of two columns to a column
void theta_f(int size_lane, byte* in_state, byte* out_state) {
  for (int x = 0; x < 5; x++) {
    for (int z = 0; z < size_lane; z++) {
      byte parity = column_parities(size_lane, in_state, x, z);
      for (int y = 0; y < 5; y++)
        out_state[index(size_lane, x, y, z)] =  in_state[index(size_lane, x, y, z)] ^ parity;
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

// rotate bits in lane by T(x,y)
void rho_f(int size_lane, byte* in_state, byte* out_state) {
  int x1, y1;
  int a11 = 1; int a12 = 0;
  int a21 = 0; int a22 = 1;
  int c11, c12, c21, c22;
  int k;

  for (int z = 0; z < size_lane; z++) {
    for (int t = 0; t < 24; t++) {
      mat_mult(a11, a12, a21, a22, 0, 1, 2, 3, &c11, &c12, &c21, &c22);
      a11 = c11; a12 = c12; a21 = c21; a22 = c22;
      x1 = a11; y1= (2*a21 + 3*a22) % 5;
      if (x1 == 0 && y1 == 0)
        k = z;
      else
        k = (z - ((t + 1)*(t + 2)) / 2) % size_lane;
      out_state[index(size_lane, x1, y1, z)] = in_state[index(size_lane, x1, y1, k)];
    }
  }
}

// reorder lanes
void pi_f(int size_lane, byte* in_state, byte* out_state) {
  int x1, y1;
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      index_pair_transform(x, y, &x1, &y1);
      for (int z = 0; z < size_lane; z++) {
        out_state[index(size_lane, x1, y1, z)] =  in_state[index(size_lane, x1, y1, z)];
      }
    }
  }
}

// non-linear transform of rows
void chi_f(int size_lane, byte* in_state, byte* out_state) {
  for (int x = 0; x < 5; x++) {
    for (int y = 0; y < 5; y++) {
      for (int z = 0; z < size_lane; z++) {
        out_state[index(size_lane, x, y, z)] =  in_state[index(size_lane, x, y, z)] ^
          (in_state[index(size_lane, (x + 1) % 5, y, z)] ^ 1) &
          in_state[index(size_lane, (x + 2) % 5, y, z)];
      }
    }
  }
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

byte local_round_constants[24] = {
  0x01, 0x1a, 0x5e, 0x70, 0x1f, 0x21, 0x79, 0x55,
  0x0e, 0x0c, 0x35, 0x26, 0x3f, 0x4f, 0x5d, 0x53,
  0x52, 0x48, 0x16, 0x66, 0x79, 0x58, 0x21, 0x74
};
int positions[7] = {0, 1, 5, 7, 15, 31, 63};
// add round constants
void iota_f(int rnd, int size_lane, byte* in_state) {
  for (int j = 0; j < 7; j++) {
    if (((((byte)1)<<j) & local_round_constants[rnd]) != 0)
      in_state[index(size_lane, 0, 0, positions[j])] ^= 1;
    }
}

void init_state(int size_lane, byte* state) {
  for (int i = 0; i < (state_size() - 1); i++)
    state[i] = 0;
}

const int num_bytes_to_hash = 16;
byte to_hash[num_bytes_to_hash] =  {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x50,
};

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

void print_state(int size_lane, byte* state_in) {
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

void keccak_f(int size_lane, byte* state_in, byte* state_out) {
  byte state1[1600];
  byte state2[1600];

  for (int round = 0;  round < 1; round++) {
    memset(state1, 0, 1600);
    printf("initial state:\n");
    print_state(size_lane, state_in);
    theta_f(size_lane, state_in, state1);
    printf("after theta:\n");
    print_state(size_lane, state1);
    memset(state2, 0, 1600);
    rho_f(size_lane, state1, state2);
    printf("after rho:\n");
    print_state(size_lane, state2);
    memset(state1, 0, 1600);
    pi_f(size_lane, state2, state1);
    printf("after pi:\n");
    print_state(size_lane, state1);
    memset(state2, 0, 1600);
    chi_f(size_lane, state1, state2);
    printf("after chi:\n");
    print_state(size_lane, state2);
    iota_f(round, size_lane, state2);
    printf("after iota:\n");
    print_state(size_lane, state2);
  }
}

void pad(int r, int size_in, int* pad_size, byte* pad_buf) {
}

int main(int an, char** av) {
  int b = state_size();
  int c = 576;
  int r = state_size() - c;

  byte state_in[1600];
  byte state_out[1600];
  memset(state_in, 0, 1600);
  memset(state_out, 0, 1600);

  printf("Keccak b= %d, c= %d, r= %d\n", b, c, r);
  byte in[8 * num_bytes_to_hash];
  memset(in, 0, 8 * num_bytes_to_hash);
  if (!bytes_to_bits(num_bytes_to_hash, to_hash, in)) {
    printf("Cant convert to bits\n");
    return 1;
  }
  printf("to hash: ");
  print_bytes(num_bytes_to_hash, to_hash);
  printf("\n");
  printf("as bits: ");
  for(int i = 0; i < 8 * num_bytes_to_hash; i++) {
    printf("%1x", in[i]);
  }
  printf("\n");

  int size_lane = lane_size(lane_exp);
  memcpy(state_in, in, 8 * num_bytes_to_hash);
  keccak_f(size_lane, state_in, state_out);

  return 0;
}

