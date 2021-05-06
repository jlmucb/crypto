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

void print_row(int lane_size, int y, int z, byte* s) {
  printf("row %d %d: ", y, z);
  for (int x= 0; x < 5; x++)
    printf("%1x", s[index(size_lane, x, y, z)];
  printf("\n");
}

void print_col(int lane_size, int x, int z, byte* s) {
  printf("column %d %d: ", x, z);
  for (int y= 0; y < 5; y++)
    printf("%1x", s[index(size_lane, x, y, z)];
  printf("\n");
}

void print_lane (int lane_size, int x, int y, byte* s) {

void print_col(int lane_size, int x, int z, byte* s) {
  printf("lane %d %d: ", x, y);
  for (int z= 0; z < lane_size; z++)
    printf("%1x", s[index(size_lane, x, y, z)];
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
    parity ^= in_state[index(lane_size, x1, y, z1)] ^ in_state[index(lane_size, x2, y, z2)];
  }
  return parity;
}

// add parity of two columns to a column
void theta_f(int size_lane, byte* in_state, byte* out_state) {
  for (int x = 0; i < 5; x++) {
    for (int z = 0; z < size_lane; z++) {
      byte parity = column_parities(size_lane, in_state, x, z);
      for (int y = 0; y < 5; y++)
        out_state[index(lane_size, x, y, z)] =  in_state[index(lane_size, x, y, z)] ^ parity;
    }
  }
}

// rotate bits in lane by T(x,y)
void rho_f(int size_lane, byte* in_state, byte* out_state) {
}

// reorder lanes
void pi_f(int size_lane, byte* in_state, byte* out_state) {
}

// non-linear transform of rows
void chi_f(int size_lane, byte* in_state, byte* out_state) {
}

// byte rc_t[];  // rc[t] = x^t mod (x^8 + x^6 + x^5 + x^4 + 1) mod 2

inline byte RC(int rnd, int j) {
  // rc_t[j + 7 * rnd]
  return 0;
}

// add round constants
void iota_f(int size_lane, byte* in_state, byte* out_state) {
}

void init_state(int size_lane, byte* state) {
  for (int i = 0; i < (state_size() - 1); i++)
    state[i] = 0;
}



