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
// File: min_entropy.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <math.h>

// Entropy tests:
//    Adaptive proportion test
//    Permutation test
//    Length of directional runs
//    # increases/decreases
//    # runs based on median
//    Length of runs based on median
//    Average collisions test
//    Max collision
//    Periodicity
//    Covariance
//    Compression
//    Chi


// s_0, s_1, ..., s_(L-1)  are samples from A= <x_0,..., x_(k-1)>
//
// Most common value: p_m = max_i {#x_i in S)/ |S|
//    p_u = min(1, p_m + 2.576sqrt([p_m(1-p_m)/(L-1)]
//    min_e = -lg(p_u)
//
// Markov
//    P_0 = #(0 in S)/L, P_1 = 1- P_0
//    P_00 = #(00 in S) / (#(00 in S) - #(01 in S))
//    P_01 = #(00 in S) / (#(00 in S) - #(01 in S))
//    P_10 = #(10 in S) / (#(10 in S) - #(11 in S))
//    P_11 = #(01 in S) / (#(11 in S) - #(11 in S))
//
//  Find p_max = most likely 128 bit sequence
//    min_e = min(-lg(p_max), 1)




