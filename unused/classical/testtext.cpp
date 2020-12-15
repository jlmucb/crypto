#include <dos.h>
#include <stdio.h>
#include <math.h>
#include <io.h>
#include <string.h>

/*
 *	(c) Copyright, 2007, John L. Manferdelli.  All Rights Reserved.
 *
 *	Venona differences
 */


/* ------------------------------------------------------------------------ */


#define BUF  2048
#define UGBUF  256
#define EC '\\'
#define CC '#'
char trans[256]= {
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,1,2,3,4,5,6,7,
	      8,9,10,11,12,13,14,15,
	      16,17,18,19,20,21,22,23,
	      24,25,26,0,0,0,0,0,
	      0,1,2,3,4,5,6,7,
	      8,9,10,11,12,13,14,15,
	      16,17,18,19,20,21,22,23,
	      24,25,26,0,0,0,0,0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0
          };


struct DiffLetters {
    char a, b;
    double xf;
};


struct DiffLetters myDifferences[26][26] = {


// Difference  0:
'e', 'e',   0.231,
't', 't',   0.132,
'a', 'a',   0.106,
'o', 'o',   0.091,
'i', 'i',   0.081,
'n', 'n',   0.067,
'h', 'h',   0.058,
's', 's',   0.053,
'r', 'r',   0.047,
'd', 'd',   0.032,
'l', 'l',   0.022,
'u', 'u',   0.014,
'w', 'w',   0.012,
'm', 'm',   0.011,
'y', 'y',   0.009,
'c', 'c',   0.007,
'f', 'f',   0.007,
'b', 'b',   0.006,
'g', 'g',   0.006,
'p', 'p',   0.005,
'v', 'v',   0.002,
'k', 'k',   0.001,
'q', 'q',   0.000,
'x', 'x',   0.000,
'j', 'j',   0.000,
'z', 'z',   0.000,


// Difference  1:
'd', 'e',   0.155,
'n', 'o',   0.145,
's', 't',   0.124,
'h', 'i',   0.098,
't', 'u',   0.084,
'e', 'f',   0.078,
'r', 's',   0.078,
'm', 'n',   0.051,
'c', 'd',   0.040,
'a', 'b',   0.036,
'o', 'p',   0.033,
'g', 'h',   0.024,
'l', 'm',   0.021,
'b', 'c',   0.008,
'k', 'l',   0.007,
'f', 'g',   0.007,
'u', 'v',   0.005,
'v', 'w',   0.002,
'w', 'x',   0.002,
'z', 'a',   0.002,
'y', 'z',   0.001,
'j', 'k',   0.000,
'i', 'j',   0.000,
'x', 'y',   0.000,
'p', 'q',   0.000,
'q', 'r',   0.000,


// Difference  2:
'r', 't',   0.186,
'c', 'e',   0.094,
'l', 'n',   0.086,
'a', 'c',   0.086,
'm', 'o',   0.070,
'y', 'a',   0.067,
'e', 'g',   0.060,
's', 'u',   0.050,
'g', 'i',   0.047,
'n', 'p',   0.041,
'f', 'h',   0.041,
'p', 'r',   0.030,
'u', 'w',   0.024,
't', 'v',   0.024,
'i', 'k',   0.020,
'w', 'y',   0.020,
'd', 'f',   0.020,
'b', 'd',   0.016,
'k', 'm',   0.009,
'o', 'q',   0.004,
'j', 'l',   0.001,
'v', 'x',   0.001,
'q', 's',   0.000,
'x', 'z',   0.000,
'h', 'j',   0.000,
'z', 'b',   0.000,


// Difference  3:
'e', 'h',   0.234,
'o', 'r',   0.133,
'a', 'd',   0.117,
'i', 'l',   0.082,
'l', 'o',   0.081,
't', 'w',   0.070,
'r', 'u',   0.052,
'b', 'e',   0.049,
'f', 'i',   0.043,
'p', 's',   0.038,
'k', 'n',   0.018,
'c', 'f',   0.018,
'd', 'g',   0.014,
'h', 'k',   0.013,
'm', 'p',   0.013,
's', 'v',   0.008,
'y', 'b',   0.005,
'v', 'y',   0.003,
'q', 't',   0.003,
'j', 'm',   0.001,
'x', 'a',   0.001,
'g', 'j',   0.001,
'z', 'c',   0.001,
'u', 'x',   0.000,
'n', 'q',   0.000,
'w', 'z',   0.000,


// Difference  4:
'a', 'e',   0.207,
'e', 'i',   0.193,
'o', 's',   0.114,
'n', 'r',   0.112,
'w', 'a',   0.062,
'h', 'l',   0.060,
'd', 'h',   0.055,
'i', 'm',   0.049,
's', 'w',   0.033,
'l', 'p',   0.022,
'p', 't',   0.021,
'u', 'y',   0.018,
'r', 'v',   0.013,
'k', 'o',   0.013,
'b', 'f',   0.009,
'y', 'c',   0.007,
't', 'x',   0.005,
'c', 'g',   0.003,
'j', 'n',   0.002,
'g', 'k',   0.001,
'q', 'u',   0.001,
'v', 'z',   0.000,
'f', 'j',   0.000,
'x', 'b',   0.000,
'm', 'q',   0.000,
'z', 'd',   0.000,


// Difference  5:
'o', 't',   0.206,
'n', 's',   0.135,
'i', 'n',   0.118,
'd', 'i',   0.101,
'h', 'm',   0.067,
'a', 'f',   0.062,
'm', 'r',   0.052,
'c', 'h',   0.051,
't', 'y',   0.051,
'r', 'w',   0.039,
'v', 'a',   0.020,
'g', 'l',   0.019,
'y', 'd',   0.019,
'p', 'u',   0.013,
'w', 'b',   0.011,
'b', 'g',   0.011,
'e', 'j',   0.008,
'f', 'k',   0.006,
's', 'x',   0.004,
'k', 'p',   0.001,
'l', 'q',   0.001,
'x', 'c',   0.001,
'j', 'o',   0.001,
'z', 'e',   0.001,
'u', 'z',   0.000,
'q', 'v',   0.000,


// Difference  6:
'i', 'o',   0.171,
'n', 't',   0.162,
'h', 'n',   0.120,
'o', 'u',   0.068,
'y', 'e',   0.068,
'u', 'a',   0.060,
'l', 'r',   0.052,
'm', 's',   0.048,
'a', 'g',   0.043,
'c', 'i',   0.043,
's', 'y',   0.033,
'e', 'k',   0.033,
'f', 'l',   0.033,
'b', 'h',   0.018,
'w', 'c',   0.015,
'g', 'm',   0.015,
'p', 'v',   0.006,
'v', 'b',   0.005,
'q', 'w',   0.002,
't', 'z',   0.002,
'r', 'x',   0.001,
'j', 'p',   0.000,
'k', 'q',   0.000,
'x', 'd',   0.000,
'd', 'j',   0.000,
'z', 'f',   0.000,


// Difference  7:
't', 'a',   0.182,
'h', 'o',   0.161,
'a', 'h',   0.132,
'e', 'l',   0.118,
'l', 's',   0.060,
'm', 't',   0.058,
'n', 'u',   0.052,
'w', 'd',   0.033,
'b', 'i',   0.030,
'r', 'y',   0.026,
'i', 'p',   0.025,
'g', 'n',   0.022,
'f', 'm',   0.020,
'o', 'v',   0.013,
'u', 'b',   0.013,
'k', 'r',   0.013,
'p', 'w',   0.012,
'y', 'f',   0.011,
'd', 'k',   0.010,
'v', 'c',   0.004,
'x', 'e',   0.001,
'c', 'j',   0.001,
'q', 'x',   0.000,
'j', 'q',   0.000,
's', 'z',   0.000,
'z', 'g',   0.000,


// Difference  8:
'a', 'i',   0.175,
's', 'a',   0.147,
'e', 'm',   0.101,
'w', 'e',   0.099,
'l', 't',   0.098,
'd', 'l',   0.054,
'f', 'n',   0.052,
'o', 'w',   0.050,
'g', 'o',   0.042,
't', 'b',   0.041,
'h', 'p',   0.032,
'u', 'c',   0.025,
'n', 'v',   0.022,
'm', 'u',   0.021,
'v', 'd',   0.013,
'k', 's',   0.009,
'y', 'g',   0.008,
'c', 'k',   0.004,
'z', 'h',   0.003,
'x', 'f',   0.001,
'q', 'y',   0.001,
'b', 'j',   0.001,
'i', 'q',   0.000,
'p', 'x',   0.000,
'j', 'r',   0.000,
'r', 'z',   0.000,


// Difference  9:
'e', 'n',   0.256,
'r', 'a',   0.162,
'i', 'r',   0.106,
't', 'c',   0.057,
'v', 'e',   0.054,
'n', 'w',   0.048,
'f', 'o',   0.040,
'd', 'm',   0.040,
'u', 'd',   0.035,
'y', 'h',   0.034,
's', 'b',   0.030,
'c', 'l',   0.028,
'l', 'u',   0.027,
'k', 't',   0.026,
'w', 'f',   0.019,
'm', 'v',   0.013,
'p', 'y',   0.009,
'g', 'p',   0.005,
'o', 'x',   0.003,
'a', 'j',   0.003,
'b', 'k',   0.003,
'z', 'i',   0.001,
'q', 'z',   0.000,
'x', 'g',   0.000,
'h', 'q',   0.000,
'j', 's',   0.000,


// Difference 10:
'e', 'o',   0.269,
'i', 's',   0.120,
't', 'd',   0.096,
'u', 'e',   0.085,
'h', 'r',   0.083,
'd', 'n',   0.063,
's', 'c',   0.040,
'y', 'i',   0.040,
'o', 'y',   0.038,
'r', 'b',   0.028,
'c', 'm',   0.023,
'm', 'w',   0.022,
'a', 'k',   0.016,
'w', 'g',   0.014,
'f', 'p',   0.012,
'k', 'u',   0.012,
'b', 'l',   0.011,
'v', 'f',   0.009,
'l', 'v',   0.006,
'q', 'a',   0.005,
'x', 'h',   0.004,
'n', 'x',   0.002,
'j', 't',   0.000,
'g', 'q',   0.000,
'p', 'z',   0.000,
'z', 'j',   0.000,


// Difference 11:
't', 'e',   0.239,
'i', 't',   0.137,
'd', 'o',   0.094,
'h', 's',   0.090,
'a', 'l',   0.082,
's', 'd',   0.071,
'e', 'p',   0.045,
'w', 'h',   0.042,
'r', 'c',   0.039,
'c', 'n',   0.031,
'n', 'y',   0.030,
'p', 'a',   0.027,
'g', 'r',   0.022,
'l', 'w',   0.019,
'u', 'f',   0.017,
'b', 'm',   0.008,
'k', 'v',   0.002,
'j', 'u',   0.001,
'v', 'g',   0.001,
'o', 'z',   0.001,
'y', 'j',   0.001,
'f', 'q',   0.000,
'q', 'b',   0.000,
'x', 'i',   0.000,
'm', 'x',   0.000,
'z', 'k',   0.000,


// Difference 12:
's', 'e',   0.206,
'o', 'a',   0.153,
'h', 't',   0.138,
'r', 'd',   0.074,
'a', 'm',   0.057,
'c', 'o',   0.056,
't', 'f',   0.055,
'w', 'i',   0.052,
'i', 'u',   0.041,
'b', 'n',   0.030,
'g', 's',   0.029,
'f', 'r',   0.027,
'd', 'p',   0.021,
'v', 'h',   0.020,
'm', 'y',   0.016,
'u', 'g',   0.014,
'p', 'b',   0.005,
'y', 'k',   0.002,
'q', 'c',   0.001,
'n', 'z',   0.001,
'l', 'x',   0.001,
'k', 'w',   0.001,
'e', 'q',   0.000,
'x', 'j',   0.000,
'j', 'v',   0.000,
'z', 'l',   0.000,


// Difference 13:
'r', 'e',   0.166,
'e', 'r',   0.163,
'a', 'n',   0.139,
'n', 'a',   0.138,
'h', 'u',   0.051,
't', 'g',   0.047,
'u', 'h',   0.043,
'g', 't',   0.037,
'b', 'o',   0.033,
's', 'f',   0.029,
'f', 's',   0.026,
'o', 'b',   0.026,
'y', 'l',   0.025,
'v', 'i',   0.024,
'i', 'v',   0.020,
'l', 'y',   0.015,
'c', 'p',   0.008,
'p', 'c',   0.004,
'z', 'm',   0.002,
'x', 'k',   0.001,
'd', 'q',   0.001,
'w', 'j',   0.001,
'j', 'w',   0.000,
'm', 'z',   0.000,
'q', 'd',   0.000,
'k', 'x',   0.000,


// Difference 14:
'e', 's',   0.203,
't', 'h',   0.163,
'a', 'o',   0.153,
'm', 'a',   0.070,
'd', 'r',   0.069,
'f', 't',   0.057,
'o', 'c',   0.054,
'u', 'i',   0.046,
'i', 'w',   0.037,
's', 'g',   0.024,
'p', 'd',   0.021,
'y', 'm',   0.020,
'r', 'f',   0.019,
'n', 'b',   0.017,
'h', 'v',   0.012,
'g', 'u',   0.010,
'k', 'y',   0.007,
'w', 'k',   0.006,
'b', 'p',   0.004,
'c', 'q',   0.002,
'x', 'l',   0.002,
'q', 'e',   0.002,
'v', 'j',   0.001,
'l', 'z',   0.000,
'j', 'x',   0.000,
'z', 'n',   0.000,


// Difference 15:
'e', 't',   0.256,
't', 'i',   0.144,
's', 'h',   0.089,
'l', 'a',   0.072,
'd', 's',   0.071,
'o', 'd',   0.071,
'h', 'w',   0.044,
'p', 'e',   0.044,
'y', 'n',   0.041,
'c', 'r',   0.037,
'n', 'c',   0.034,
'a', 'p',   0.029,
'w', 'l',   0.022,
'r', 'g',   0.021,
'f', 'u',   0.012,
'm', 'b',   0.004,
'g', 'v',   0.003,
'x', 'm',   0.002,
'z', 'o',   0.002,
'u', 'j',   0.001,
'v', 'k',   0.001,
'q', 'f',   0.001,
'k', 'z',   0.000,
'b', 'q',   0.000,
'i', 'x',   0.000,
'j', 'y',   0.000,


// Difference 16:
'o', 'e',   0.265,
'd', 't',   0.112,
's', 'i',   0.107,
'r', 'h',   0.091,
'e', 'u',   0.091,
'n', 'd',   0.060,
'c', 's',   0.051,
'y', 'o',   0.041,
'i', 'y',   0.039,
'm', 'c',   0.030,
'b', 'r',   0.016,
'w', 'm',   0.015,
'k', 'a',   0.015,
'p', 'f',   0.011,
'v', 'l',   0.011,
'l', 'b',   0.010,
'g', 'w',   0.009,
'u', 'k',   0.007,
't', 'j',   0.006,
'f', 'v',   0.005,
'h', 'x',   0.003,
'x', 'n',   0.002,
'a', 'q',   0.001,
'q', 'g',   0.001,
'j', 'z',   0.000,
'z', 'p',   0.000,


// Difference 17:
'n', 'e',   0.251,
'a', 'r',   0.154,
'r', 'i',   0.111,
'c', 't',   0.075,
'w', 'n',   0.057,
'o', 'f',   0.052,
'd', 'u',   0.047,
'm', 'd',   0.044,
'u', 'l',   0.034,
'b', 's',   0.027,
'h', 'y',   0.026,
'l', 'c',   0.025,
'e', 'v',   0.023,
'f', 'w',   0.023,
't', 'k',   0.016,
'y', 'p',   0.010,
'p', 'g',   0.008,
'v', 'm',   0.006,
'x', 'o',   0.005,
'i', 'z',   0.003,
'g', 'x',   0.001,
'j', 'a',   0.001,
'q', 'h',   0.000,
'k', 'b',   0.000,
's', 'j',   0.000,
'z', 'q',   0.000,


// Difference 18:
'i', 'a',   0.158,
'a', 's',   0.143,
'm', 'e',   0.103,
't', 'l',   0.099,
'e', 'w',   0.092,
'l', 'd',   0.059,
'w', 'o',   0.054,
'b', 't',   0.052,
'n', 'f',   0.041,
'o', 'g',   0.036,
'u', 'm',   0.033,
'p', 'h',   0.033,
'c', 'u',   0.029,
'd', 'v',   0.022,
'v', 'n',   0.019,
's', 'k',   0.010,
'k', 'c',   0.006,
'g', 'y',   0.003,
'y', 'q',   0.003,
'f', 'x',   0.001,
'q', 'i',   0.001,
'x', 'p',   0.001,
'r', 'j',   0.001,
'j', 'b',   0.000,
'h', 'z',   0.000,
'z', 'r',   0.000,


// Difference 19:
'a', 't',   0.194,
'o', 'h',   0.136,
'h', 'a',   0.128,
'l', 'e',   0.115,
't', 'm',   0.079,
's', 'l',   0.065,
'u', 'n',   0.046,
'p', 'i',   0.036,
'y', 'r',   0.030,
'd', 'w',   0.028,
'n', 'g',   0.028,
'v', 'o',   0.022,
'i', 'b',   0.021,
'm', 'f',   0.017,
'f', 'y',   0.011,
'w', 'p',   0.010,
'e', 'x',   0.009,
'r', 'k',   0.008,
'c', 'v',   0.006,
'b', 'u',   0.006,
'k', 'd',   0.003,
'z', 's',   0.001,
'q', 'j',   0.000,
'x', 'q',   0.000,
'g', 'z',   0.000,
'j', 'c',   0.000,


// Difference 20:
'o', 'i',   0.170,
't', 'n',   0.163,
'n', 'h',   0.137,
'r', 'l',   0.069,
'a', 'u',   0.062,
'e', 'y',   0.056,
'u', 'o',   0.056,
's', 'm',   0.054,
'i', 'c',   0.044,
'y', 's',   0.042,
'g', 'a',   0.033,
'c', 'w',   0.027,
'h', 'b',   0.021,
'k', 'e',   0.020,
'm', 'g',   0.018,
'l', 'f',   0.018,
'b', 'v',   0.004,
'w', 'q',   0.002,
'x', 'r',   0.002,
'v', 'p',   0.002,
'j', 'd',   0.001,
'f', 'z',   0.000,
'd', 'x',   0.000,
'p', 'j',   0.000,
'q', 'k',   0.000,
'z', 't',   0.000,


// Difference 21:
't', 'o',   0.221,
'n', 'i',   0.154,
's', 'n',   0.137,
'i', 'd',   0.077,
'h', 'c',   0.061,
'y', 't',   0.057,
'm', 'h',   0.050,
'r', 'm',   0.049,
'w', 'r',   0.047,
'f', 'a',   0.047,
'l', 'g',   0.020,
'a', 'v',   0.018,
'd', 'y',   0.016,
'u', 'p',   0.015,
'b', 'w',   0.009,
'p', 'k',   0.005,
'o', 'j',   0.004,
'x', 's',   0.003,
'g', 'b',   0.003,
'q', 'l',   0.001,
'k', 'f',   0.001,
'e', 'z',   0.001,
'j', 'e',   0.001,
'z', 'u',   0.001,
'c', 'x',   0.000,
'v', 'q',   0.000,


// Difference 22:
'e', 'a',   0.232,
'i', 'e',   0.170,
's', 'o',   0.109,
'r', 'n',   0.093,
'l', 'h',   0.066,
'a', 'w',   0.061,
'h', 'd',   0.054,
'm', 'i',   0.044,
't', 'p',   0.039,
'w', 's',   0.038,
'v', 'r',   0.016,
'y', 'u',   0.014,
'p', 'l',   0.013,
'o', 'k',   0.012,
'c', 'y',   0.012,
'f', 'b',   0.010,
'g', 'c',   0.009,
'x', 't',   0.003,
'k', 'g',   0.003,
'j', 'f',   0.002,
'q', 'm',   0.001,
'n', 'j',   0.001,
'd', 'z',   0.000,
'u', 'q',   0.000,
'b', 'x',   0.000,
'z', 'v',   0.000,


// Difference 23:
'h', 'e',   0.193,
'd', 'a',   0.123,
'r', 'o',   0.114,
'l', 'i',   0.103,
'e', 'b',   0.073,
'w', 't',   0.072,
'o', 'l',   0.070,
'u', 'r',   0.055,
'i', 'f',   0.041,
's', 'p',   0.031,
'n', 'k',   0.020,
'g', 'd',   0.018,
'b', 'y',   0.016,
'p', 'm',   0.016,
'k', 'h',   0.016,
'f', 'c',   0.015,
'v', 's',   0.009,
'a', 'x',   0.006,
'y', 'v',   0.004,
'q', 'n',   0.001,
'x', 'u',   0.001,
't', 'q',   0.001,
'c', 'z',   0.000,
'j', 'g',   0.000,
'm', 'j',   0.000,
'z', 'w',   0.000,


// Difference 24:
't', 'r',   0.166,
'e', 'c',   0.106,
'n', 'l',   0.092,
'o', 'm',   0.077,
'a', 'y',   0.061,
'u', 's',   0.061,
'c', 'a',   0.058,
'g', 'e',   0.054,
'h', 'f',   0.045,
'p', 'n',   0.038,
'f', 'd',   0.036,
'k', 'i',   0.035,
'r', 'p',   0.032,
'w', 'u',   0.031,
'v', 't',   0.026,
'i', 'g',   0.022,
'y', 'w',   0.022,
'd', 'b',   0.020,
'm', 'k',   0.010,
'j', 'h',   0.003,
'l', 'j',   0.003,
'q', 'o',   0.003,
's', 'q',   0.000,
'x', 'v',   0.000,
'b', 'z',   0.000,
'z', 'x',   0.000,


// Difference 25:
't', 's',   0.157,
'e', 'd',   0.141,
'o', 'n',   0.130,
'i', 'h',   0.115,
'f', 'e',   0.084,
's', 'r',   0.078,
'u', 't',   0.073,
'b', 'a',   0.034,
'm', 'l',   0.034,
'n', 'm',   0.031,
'h', 'g',   0.030,
'p', 'o',   0.028,
'd', 'c',   0.025,
'g', 'f',   0.010,
'l', 'k',   0.007,
'v', 'u',   0.007,
'c', 'b',   0.006,
'j', 'i',   0.003,
'w', 'v',   0.003,
'a', 'z',   0.002,
'k', 'j',   0.001,
'x', 'w',   0.001,
'y', 'x',   0.001,
'r', 'q',   0.000,
'q', 'p',   0.000,
'z', 'y',   0.000
};


/* ------------------------------------------------------------------------ */


class charIO {
public:
    int         in;
    char        ugbuf[UGBUF];
    int         ugnc;
    char        buf[BUF];
    int         nc;
    char        *cpos;
    int         nlines;

    int         nNTC;

    int         jgetc();
    int         jungetc(int ugc);
    int         getNTC();
    int         openFile(char*);
    void        closeFile();
    charIO()    {nc=0; ugnc= 0; nlines=0; nNTC= 0;};
};

/* ------------------------------------------------------------------------ */


int charIO::jgetc()

{
	int i;

	if(ugnc>0)
		return((int) ugbuf[--ugnc]);

	if(nc<=0) {
		if((nc=read(in,buf,BUF))<=0)
			return(-1);
		cpos= buf;
		}
	i= *(cpos++);
	nc--;
	if(i==((int) '\n'))
		nlines++;
	return(i);
}


int charIO::jungetc(int ugc)

{
	if(ugnc>=UGBUF)
		return(-1);
	ugbuf[ugnc++]= ugc;
	return(ugc);
}


int charIO:: getNTC() 
{
    int i, j;

    for(;;) {
        i= jgetc();
        if(i<0)
            return(-1);
        j= trans[i];
        if(j>0)
            return(j);
    }
}


int   charIO::openFile(char* szFile)
{
    int i;

	if((i=open(szFile,0))<0) {
        return(-1);
		}
    in= i;
    return(1);
}


void  charIO::closeFile()
{
    close(in);
    in= 0;
    return;
}


/* ------------------------------------------------------------------------ */


void printTrialText(int n, int iDiffs[])
{
    int i, j, k, m, d;
    char c;

    printf("TrialText\n");
    //myDifferences[d][j]
    for(i=0;i<26;i++) {
         for(k=0; k<n; k++) {
              d= iDiffs[k];
              c= myDifferences[d][i].a;
              printf("%c", c);
              }
         printf("  %2d (1)\n", i);
         for(k=0; k<n; k++) {
             d= iDiffs[k];
             c= myDifferences[d][i].b;
             printf("%c", c);
         }
        printf("  %2d (2)\n", i);
        printf("---------\n");
    }

    printf("\n");
}


int main(int an, char** av)

{
    charIO  oFile1;
    charIO  oFile2;
    int     nNTC= 0;
    int     iNTC1;
    int     iNTC2;
    int     i,j,k,n;
    int     iDiffs[20];
    bool    fOneline= false;

	if(an<3) {
		printf("Syntax: testtext Input-file1 Input-file2\n");
		return(1);
		}
	if(oFile1.openFile(av[1])<0) {
		printf("Can't open %s\n",av[1]);
		return(1);
		}
	if(oFile2.openFile(av[2])<0) {
		printf("Can't open %s\n",av[2]);
		return(1);
		}
    if(an>=4 && strcmp("oneline", av[3])==0) {
            fOneline= true;
            }

    printf("Testtext %s %s\n\n",av[1],av[2]);


    n= 0;
    for(;;) {
	    iNTC1= oFile1.getNTC();
	    iNTC2= oFile2.getNTC();
        if(iNTC1<0 || iNTC2<0)
            break;
        if(iNTC1<1 || iNTC1>26)
            continue;
        if(iNTC2<1 || iNTC2>26)
            continue;
        nNTC++;
        if((nNTC%15)==0)
            printf("\n");
        iDiffs[n++]= (iNTC2-iNTC1+26)%26;
        if(n>=20) {
            printTrialText(n,iDiffs);
            n= 0;
            if(fOneline)
                break;
        }
    }
    if(n>0) {
        printTrialText(n,iDiffs);
        }
    printf("\n");

	oFile1.closeFile();
	oFile2.closeFile();
	return(0);
}


/* ------------------------------------------------------------------------ */

