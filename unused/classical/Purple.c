/*
  Program to simulate Purple cipher
  Consistent with the samples given in the article
  Purple Revealed: Simulation and Computer-Aided
  Cryptanalysis of Angooki Taipu B, Freeman, Sullivan, and Weierud,
  Cryptologia, Vol. XXVII, No. 1, January 2003
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void getInversePerm(int invPerm[], int perm[], int n);
int stepSwitch(int a, int b);


// Purple perms --- should not change
#define SIXES_0 {1,0,2,4,3,5}
#define SIXES_1 {4,3,1,5,2,0}
#define SIXES_2 {0,4,5,2,1,3}
#define SIXES_3 {3,2,1,0,5,4}
#define SIXES_4 {2,5,0,3,4,1}
#define SIXES_5 {1,0,4,5,3,2}
#define SIXES_6 {4,3,5,2,1,0}
#define SIXES_7 {2,5,0,3,4,1}
#define SIXES_8 {5,2,4,1,0,3}
#define SIXES_9 {4,3,2,0,1,5}
#define SIXES_10 {1,0,5,2,3,4}
#define SIXES_11 {5,4,3,1,0,2}
#define SIXES_12 {1,2,0,4,5,3}
#define SIXES_13 {3,1,4,0,2,5}
#define SIXES_14 {0,2,3,5,4,1}
#define SIXES_15 {4,5,2,1,0,3}
#define SIXES_16 {5,1,3,4,2,0}
#define SIXES_17 {3,0,1,2,4,5}
#define SIXES_18 {0,1,2,5,3,4}
#define SIXES_19 {1,4,0,3,5,2}
#define SIXES_20 {2,3,5,4,1,0}
#define SIXES_21 {0,4,1,3,5,2}
#define SIXES_22 {3,5,4,1,2,0}
#define SIXES_23 {2,3,5,0,4,1}
#define SIXES_24 {5,1,3,2,0,4}

// Purple perms --- should not change
#define TWENTIES_L_0 {3,6,12,5,16,0,7,10,9,4,15,17,8,2,14,11,19,13,1,18}
#define TWENTIES_L_1 {5,16,8,0,1,17,19,9,18,14,11,12,13,4,7,2,3,10,15,6}
#define TWENTIES_L_2 {1,18,11,16,19,3,12,14,17,10,5,7,2,13,4,8,0,9,6,15}
#define TWENTIES_L_3 {13,8,0,3,12,4,16,6,11,15,14,9,17,1,18,5,10,19,7,2}
#define TWENTIES_L_4 {18,15,9,7,5,1,14,2,19,8,17,13,4,12,11,10,16,6,0,3}
#define TWENTIES_L_5 {19,0,7,17,18,6,4,11,2,12,1,10,9,3,13,14,15,8,5,16}
#define TWENTIES_L_6 {7,9,18,11,10,2,1,16,4,5,12,19,6,15,17,0,8,3,13,14}
#define TWENTIES_L_7 {0,19,13,14,6,11,2,12,15,9,16,4,10,5,8,3,17,7,18,1}
#define TWENTIES_L_8 {8,13,19,16,11,14,6,3,1,17,2,15,18,7,10,9,0,5,12,4}
#define TWENTIES_L_9 {16,12,4,6,9,15,10,1,3,7,19,0,14,8,18,13,2,11,17,5}
#define TWENTIES_L_10 {1,4,12,7,15,16,17,8,6,10,3,18,11,14,9,2,5,13,19,0}
#define TWENTIES_L_11 {17,3,15,1,0,6,11,10,16,13,18,8,4,9,2,7,12,14,5,19}
#define TWENTIES_L_12 {15,5,10,19,16,18,9,7,8,2,6,14,13,11,0,4,1,12,3,17}
#define TWENTIES_L_13 {12,10,3,8,11,7,2,4,13,16,0,1,19,17,5,6,18,15,14,9}
#define TWENTIES_L_14 {9,2,17,4,8,14,3,5,11,19,10,0,16,15,6,1,13,18,7,12}
#define TWENTIES_L_15 {3,16,14,15,17,19,13,0,12,18,5,4,10,7,1,9,6,2,11,8}
#define TWENTIES_L_16 {14,12,1,18,2,13,0,19,10,11,9,16,5,8,15,17,4,3,6,7}
#define TWENTIES_L_17 {11,6,5,2,18,12,15,17,14,0,8,13,1,3,16,19,7,4,9,10}
#define TWENTIES_L_18 {10,11,15,13,14,9,1,18,2,7,12,3,0,6,19,5,17,16,8,4}
#define TWENTIES_L_19 {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19}
#define TWENTIES_L_20 {6,17,11,10,3,19,8,13,0,4,15,2,7,18,9,12,5,14,16,1}
#define TWENTIES_L_21 {4,2,16,17,7,10,5,15,12,6,13,14,3,19,1,18,9,0,8,11}
#define TWENTIES_L_22 {8,15,18,9,6,13,12,19,7,3,4,10,11,16,17,0,14,1,2,5}
#define TWENTIES_L_23 {2,7,9,12,0,8,18,1,5,17,19,6,15,10,3,14,11,16,4,13}
#define TWENTIES_L_24 {18,14,6,2,13,11,17,3,4,1,7,5,19,0,12,16,8,15,10,9}

// Purple perms --- should not change
#define TWENTIES_M_0 {2,7,6,17,3,14,19,9,1,8,10,12,15,18,0,13,4,11,5,16}
#define TWENTIES_M_1 {16,3,19,4,10,1,13,6,5,14,11,0,18,17,2,7,9,15,8,12}
#define TWENTIES_M_2 {5,13,17,0,2,16,14,3,15,18,12,6,10,9,7,4,11,1,19,8}
#define TWENTIES_M_3 {13,2,9,18,11,0,5,10,16,12,1,7,19,4,8,17,14,6,15,3}
#define TWENTIES_M_4 {8,1,3,5,16,12,0,17,4,19,13,9,2,7,15,14,6,10,18,11}
#define TWENTIES_M_5 {10,11,13,14,0,18,3,8,5,4,16,15,9,2,19,12,1,17,6,7}
#define TWENTIES_M_6 {17,6,2,1,19,15,18,0,7,10,3,8,5,12,13,9,11,16,4,14}
#define TWENTIES_M_7 {1,16,10,15,9,19,11,5,17,3,7,18,12,6,4,2,13,8,14,0}
#define TWENTIES_M_8 {9,5,16,6,4,11,2,1,0,15,10,19,7,14,3,18,8,13,12,17}
#define TWENTIES_M_9 {16,19,11,12,8,9,15,4,10,0,2,1,14,17,18,5,7,3,13,6}
#define TWENTIES_M_10 {7,15,19,3,12,6,1,18,13,17,0,10,8,2,11,14,16,4,9,5}
#define TWENTIES_M_11 {14,0,1,19,15,13,8,16,2,3,9,11,4,5,6,7,17,12,18,10}
#define TWENTIES_M_12 {3,12,5,8,14,10,9,11,7,1,15,16,6,13,2,0,4,18,17,19}
#define TWENTIES_M_13 {18,9,4,13,17,8,14,19,6,7,12,3,5,11,16,1,10,2,0,15}
#define TWENTIES_M_14 {4,18,16,15,10,7,5,12,11,6,8,2,17,1,9,19,14,0,3,13}
#define TWENTIES_M_15 {19,3,1,4,5,17,15,14,8,9,6,13,16,7,12,11,18,10,2,0}
#define TWENTIES_M_16 {12,4,0,2,7,1,10,15,14,16,17,5,18,3,13,6,19,8,11,9}
#define TWENTIES_M_17 {6,11,18,10,0,13,12,17,3,4,14,9,8,15,1,16,5,19,7,2}
#define TWENTIES_M_18 {11,8,14,7,4,15,16,6,12,17,19,18,2,0,9,10,3,5,13,1}
#define TWENTIES_M_19 {2,17,9,16,6,3,18,0,19,10,1,12,11,5,14,15,8,7,4,13}
#define TWENTIES_M_20 {3,14,10,17,18,2,7,16,9,13,11,4,12,19,5,8,0,15,1,6}
#define TWENTIES_M_21 {0,19,12,11,1,4,9,7,8,14,5,2,13,6,18,17,15,16,10,3}
#define TWENTIES_M_22 {15,13,8,9,7,5,17,1,18,2,4,19,3,16,10,0,12,14,6,11}
#define TWENTIES_M_23 {7,8,15,19,13,11,6,2,12,5,18,14,1,10,17,3,16,9,0,4}
#define TWENTIES_M_24 {1,10,7,5,9,19,4,13,15,11,14,17,0,8,3,6,2,12,16,18}

// Purple perms --- should not change
#define TWENTIES_R_0 {5,19,3,14,16,7,0,12,13,6,2,9,11,17,18,8,10,15,1,4}
#define TWENTIES_R_1 {8,3,7,11,19,17,13,6,10,12,14,4,5,2,0,16,1,18,9,15}
#define TWENTIES_R_2 {4,0,13,6,18,10,14,17,8,7,1,3,12,9,11,15,19,16,5,2}
#define TWENTIES_R_3 {15,9,1,4,10,6,19,11,3,14,13,2,18,12,16,0,17,8,7,5}
#define TWENTIES_R_4 {17,11,5,3,14,8,12,10,4,13,19,0,7,16,6,2,18,1,15,9}
#define TWENTIES_R_5 {18,12,17,16,2,3,5,4,1,11,14,6,0,8,15,19,7,9,13,10}
#define TWENTIES_R_6 {10,2,12,0,7,14,1,8,17,5,18,11,13,15,3,9,4,19,6,16}
#define TWENTIES_R_7 {11,16,19,2,8,1,18,6,0,3,17,9,14,7,13,5,10,4,15,12}
#define TWENTIES_R_8 {12,13,10,15,0,11,8,9,16,17,6,7,4,1,5,18,3,2,19,14}
#define TWENTIES_R_9 {9,12,4,13,6,15,17,16,2,8,0,5,18,10,7,1,11,3,14,19}
#define TWENTIES_R_10 {6,8,2,17,5,19,15,1,18,9,7,10,16,4,3,11,14,12,0,13}
#define TWENTIES_R_11 {0,7,14,9,10,12,5,15,4,19,11,1,3,6,8,13,2,16,17,18}
#define TWENTIES_R_12 {4,6,0,1,18,13,11,7,15,2,19,3,9,8,14,12,16,5,10,17}
#define TWENTIES_R_13 {16,11,19,5,3,2,10,18,0,4,1,12,8,14,9,17,6,13,7,15}
#define TWENTIES_R_14 {14,17,9,12,16,18,7,0,11,8,15,5,1,2,10,3,13,19,4,6}
#define TWENTIES_R_15 {15,4,18,3,13,8,17,16,14,19,9,7,6,12,2,1,5,0,11,10}
#define TWENTIES_R_16 {1,14,15,10,12,4,2,19,9,16,13,8,5,0,17,6,11,7,18,3}
#define TWENTIES_R_17 {2,5,8,7,11,16,4,9,15,10,3,13,17,19,12,14,0,6,1,18}
#define TWENTIES_R_18 {7,2,11,19,17,5,6,13,12,0,4,18,10,3,1,8,15,14,16,9}
#define TWENTIES_R_19 {19,6,13,8,7,3,9,2,1,15,5,4,16,11,14,10,12,18,17,0}
#define TWENTIES_R_20 {12,18,16,11,15,9,14,3,17,5,0,19,2,7,10,4,13,6,8,1}
#define TWENTIES_R_21 {8,10,9,4,1,13,16,14,19,2,12,17,15,18,6,0,7,5,3,11}
#define TWENTIES_R_22 {6,15,18,9,4,0,12,17,5,1,10,16,14,13,19,3,8,11,2,7}
#define TWENTIES_R_23 {3,17,14,16,2,11,1,0,6,18,8,15,19,5,4,7,9,10,12,13}
#define TWENTIES_R_24 {13,1,6,18,9,12,3,5,7,11,16,14,0,4,15,10,2,17,19,8}

// these should not change
#define SIXES "AEIOUY"
#define TWENTIES "BCDFGHJKLMNPQRSTVWXZ"
#define LETTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


// These plugboards are part of the key
// Note that these are the inverse plugboards, assuming the
// the "forward" plugboard is in the direction from the keyboard
// to the switches (this is done for consistency with the
// Cryptologia article cited above). Note also that the 
// permutation is for "ABCD...Z", not in terms of the 6-20
// split (this differs from the article---so much for consistency)
// Note that here the equivalent of the plugboard setting
// on page 24 of the Cryptologia article is to set both
// INPUT_PLUGBOARD_INVERSE and OUTPUT_PLUGBOARD_INVERSE to
// "NXEQOLHBKRMPDITCJASVYWGZUF"
// Note that here the plugging is given relative to
// "ABCDEFGHIJKLMNOPQRSTUVWXYZ" whereas the
// Cryptologia article gives it relative to
// "AEIOUYBCDFGHJKLMNPQRSTVWXZ", i.e., the sixes and twenties
//#define INPUT_PLUGBOARD_INVERSE "NXEQOLHBKRMPDITCJASVYWGZUF"
//#define OUTPUT_PLUGBOARD_INVERSE "NXEQOLHBKRMPDITCJASVYWGZUF"
#define INPUT_PLUGBOARD_INVERSE "YIJKRTUXPOEFGQVZNHWALMBCSD"
#define OUTPUT_PLUGBOARD_INVERSE "YIJKRTUXPOEFGQVZNHWALMBCSD"

// Print flags
// print permutations
//#define PR_PERMS
// print output for each step of encryption/decryption
//#define PR_STEPS
// print the key
#define PR_KEY


// function prototypes
void getInversePerm(int invPerm[], int perm[], int n);
int stepRotor(int a, int b);


int main(int argc, const char *argv[])
{
	FILE *in;

	int i,
		j,
		n,
		temp,
		flag,
		cur_S,
		init_S,
		init_L,
		init_M,
		init_R,
		fast,
		medium,
		slow;
	
	int S[25][6] = {SIXES_0, SIXES_1, SIXES_2, SIXES_3, SIXES_4,
					SIXES_5, SIXES_6, SIXES_7, SIXES_8, SIXES_9,
					SIXES_10, SIXES_11, SIXES_12, SIXES_13, SIXES_14,
					SIXES_15, SIXES_16, SIXES_17, SIXES_18, SIXES_19,
					SIXES_20, SIXES_21, SIXES_22, SIXES_23, SIXES_24},
		L[25][20] = {TWENTIES_L_0, TWENTIES_L_1, TWENTIES_L_2, TWENTIES_L_3, TWENTIES_L_4, 
					 TWENTIES_L_5, TWENTIES_L_6, TWENTIES_L_7, TWENTIES_L_8, TWENTIES_L_9, 
					 TWENTIES_L_10, TWENTIES_L_11, TWENTIES_L_12, TWENTIES_L_13, TWENTIES_L_14, 
					 TWENTIES_L_15, TWENTIES_L_16, TWENTIES_L_17, TWENTIES_L_18, TWENTIES_L_19, 
					 TWENTIES_L_20, TWENTIES_L_21, TWENTIES_L_22, TWENTIES_L_23, TWENTIES_L_24},
		M[25][20] = {TWENTIES_M_0, TWENTIES_M_1, TWENTIES_M_2, TWENTIES_M_3, TWENTIES_M_4, 
					 TWENTIES_M_5, TWENTIES_M_6, TWENTIES_M_7, TWENTIES_M_8, TWENTIES_M_9, 
					 TWENTIES_M_10, TWENTIES_M_11, TWENTIES_M_12, TWENTIES_M_13, TWENTIES_M_14, 
					 TWENTIES_M_15, TWENTIES_M_16, TWENTIES_M_17, TWENTIES_M_18, TWENTIES_M_19, 
					 TWENTIES_M_20, TWENTIES_M_21, TWENTIES_M_22, TWENTIES_M_23, TWENTIES_M_24},
		R[25][20] = {TWENTIES_R_0, TWENTIES_R_1, TWENTIES_R_2, TWENTIES_R_3, TWENTIES_R_4, 
					 TWENTIES_R_5, TWENTIES_R_6, TWENTIES_R_7, TWENTIES_R_8, TWENTIES_R_9, 
					 TWENTIES_R_10, TWENTIES_R_11, TWENTIES_R_12, TWENTIES_R_13, TWENTIES_R_14, 
					 TWENTIES_R_15, TWENTIES_R_16, TWENTIES_R_17, TWENTIES_R_18, TWENTIES_R_19, 
					 TWENTIES_R_20, TWENTIES_R_21, TWENTIES_R_22, TWENTIES_R_23, TWENTIES_R_24},
		S_inv[25][6],
		L_inv[25][20],
		M_inv[25][20],
		R_inv[25][20],
		cur[3],// cur[0] for L, cur[1] for M, cur[2] for R
		inPlug[26],
		inPlug_inv[26],
		outPlug[26],
		outPlug_inv[26],
		split[26],
		unsplit[26];
		
	char twenty[20] = TWENTIES,
		 six[6] = SIXES,
		 letter[26] = LETTERS,
		 inputPlugboardInverse[26] = INPUT_PLUGBOARD_INVERSE,
		 outputPlugboardInverse[26] = OUTPUT_PLUGBOARD_INVERSE,
		 infname[100];
		 
	unsigned char inChar,
				  outChar;

	if(argc != 8)
	{
oops:   fprintf(stderr, "\n\nUsage: %s speed init_S init_L init_M init_R flag infile\n\n", 
				argv[0]);
		fprintf(stderr, "where speed == fast, medium, slow switches, e.g., LMR (no space, no repeats)\n");
		fprintf(stderr, "      init_S == initial position for sixes switch (0 thru 24)\n");
		fprintf(stderr, "      init_L == initial position for L switch (0 thru 24)\n");
		fprintf(stderr, "      init_M == initial position for M switch (0 thru 24)\n");
		fprintf(stderr, "      init_R == initial position for R switch (0 thru 24)\n");
		fprintf(stderr, "      flag == 0 to encrypt, 1 to decrypt\n");
		fprintf(stderr, "      infile == input file name\n\n");
		fprintf(stderr, "For example: %s LMR 21 11 3 12 0 plain.txt\n\n", argv[0]);
		fprintf(stderr, "Note: input file must contain only upper case A thru Z\n\n");
		exit(0);
	}

	if(strlen(argv[1]) != 3)
	{
		fprintf(stderr, "\nError --- SMF must be three characters, L, M, R in some order\n");
		goto oops;
	}
	
	fast = argv[1][0] - 65;
	if(fast != 11 && fast != 12 && fast != 17)
	{
		fprintf(stderr, "\nError --- SMF must be three characters, L, M, R in some order\n");
		goto oops;
	}
	fast -= 11;
	if(fast == 6)
	{
		fast = 2;
	}

	medium = argv[1][1] - 65;
	if(medium != 11 && medium != 12 && medium != 17)
	{
		fprintf(stderr, "\nError --- SMF must be three characters, L, M, R in some order\n");
		goto oops;
	}
	medium -= 11;
	if(medium == 6)
	{
		medium = 2;
	}

	slow = argv[1][2] - 65;
	if(slow != 11 && slow != 12 && slow != 17)
	{
		fprintf(stderr, "\nError --- SMF must be three characters, L, M, R in some order\n");
		goto oops;
	}
	slow -= 11;
	if(slow == 6)
	{
		slow = 2;
	}
	
	if(slow == medium || slow == fast || medium == fast)
	{
		fprintf(stderr, "\nError --- SMF must be three characters, L, M, R, no repeats\n");
		goto oops;
	}

	init_S = atoi(argv[2]);
	if(init_S < 0 || init_S > 24)
	{
		fprintf(stderr, "\nError --- init_S must be in the range 0 to 24\n");
		goto oops;
	}

	init_L = atoi(argv[3]);
	if(init_L < 0 || init_L > 24)
	{
		fprintf(stderr, "\nError --- init_L must be in the range 0 to 24\n");
		goto oops;
	}

	init_M = atoi(argv[4]);
	if(init_M < 0 || init_M > 24)
	{
		fprintf(stderr, "\nError --- init_M must be in the range 0 to 24\n");
		goto oops;
	}

	init_R = atoi(argv[5]);
	if(init_R < 0 || init_R > 24)
	{
		fprintf(stderr, "\nError --- init_R must be in the range 0 to 24\n");
		goto oops;
	}

	flag = atoi(argv[6]);
	if(flag < 0 || flag > 1)
	{
		fprintf(stderr, "\nError --- flag must be 0 or 1\n");
		goto oops;
	}

	printf("(fast,medium,slow) = (%d,%d,%d), (init_S,init_L,init_M,init_R) = (%d,%d,%d,%d)\n", 
		fast, medium, slow, init_S, init_L, init_M, init_R);

	sprintf(infname, argv[7]);
    in = fopen(infname, "r");
    if(in == NULL)
    {
        fprintf(stderr, "\n\nError opening file %s\nTry again\n\n", infname);
        goto oops;
    }

	// note: each S[i] is a permutation of {0,1,...,5}
	// each L{i], M[i], and R[i] is a permutation of {0,1,2,...,19}
	for(i = 0; i < 25; ++i)
	{
		getInversePerm(S_inv[i], S[i], 6);
		for(j = 0; j < 6; ++j)
		{
			// the sixes are the high 6 numbers: 20,21,22,23,24,25
			S[i][j] += 20;
			S_inv[i][j] += 20;
		}
		getInversePerm(L_inv[i], L[i], 20);
		getInversePerm(M_inv[i], M[i], 20);
		getInversePerm(R_inv[i], R[i], 20);

	}// next i
	
	for(i = 0; i < 26; ++i)
	{
		inPlug_inv[i] = (int)inputPlugboardInverse[i] - 65;
		outPlug_inv[i] = (int)outputPlugboardInverse[i] - 65;
		
	}// next i

	getInversePerm(inPlug, inPlug_inv, 26);
	getInversePerm(outPlug, outPlug_inv, 26);
	
	// split is used to split the twenties from the sixes
	// with the twenties in positions 0 thru 19
	// and the sixes in positions 20 thru 25
	for(i = 0; i < 20; ++i)
	{
		unsplit[i] = (int)twenty[i] - 65;
	}
	for(i = 0; i < 6; ++i)
	{
		unsplit[i + 20] = (int)six[i] - 65;
	}
	getInversePerm(split, unsplit, 26);

#ifdef PR_PERMS
	printf("S perms\n");
	for(i = 0; i < 25; ++i)
	{
		printf("S[%2d] = ", i);
		for(j = 0; j < 6; ++j)
		{
			printf("%c", six[S[i][j] - 20]);
//			printf("%d ", S[i][j] - 20);
		}
		printf("\n");
	}
	printf("\n");
	printf("S_inv perms\n");
	for(i = 0; i < 25; ++i)
	{
		printf("S_inv[%2d] = ", i);
		for(j = 0; j < 6; ++j)
		{
			printf("%c", six[S_inv[i][j] - 20]);
//			printf("%d ", S_inv[i][j] - 20);
		}
		printf("\n");
	}
	printf("\n");
	printf("L perms\n");
	for(i = 0; i < 25; ++i)
	{
		printf("L[%2d] = ", i);
		for(j = 0; j < 20; ++j)
		{
			printf("%c", twenty[L[i][j]]);
//			printf("%d ", L[i][j]);
		}
		printf("\n");
	}
	printf("\n");
	printf("L_inv perms\n");
	for(i = 0; i < 25; ++i)
	{
		printf("L_inv[%2d] = ", i);
		for(j = 0; j < 20; ++j)
		{
			printf("%c", twenty[L_inv[i][j]]);
//			printf("%d ", L_inv[i][j]);
		}
		printf("\n");
	}
	printf("\n");
	printf("M perms\n");
	for(i = 0; i < 25; ++i)
	{
		printf("M[%2d] = ", i);
		for(j = 0; j < 20; ++j)
		{
			printf("%c", twenty[M[i][j]]);
//			printf("%d ", M[i][j]);
		}
		printf("\n");
	}
	printf("\n");
	printf("M_inv perms\n");
	for(i = 0; i < 25; ++i)
	{
		printf("M_inv[%2d] = ", i);
		for(j = 0; j < 20; ++j)
		{
			printf("%c", twenty[M_inv[i][j]]);
//			printf("%d ", M_inv[i][j]);
		}
		printf("\n");
	}
	printf("\n");
	printf("R perms\n");
	for(i = 0; i < 25; ++i)
	{
		printf("R[%2d] = ", i);
		for(j = 0; j < 20; ++j)
		{
			printf("%c", twenty[R[i][j]]);
//			printf("%d ", R[i][j]);
		}
		printf("\n");
	}
	printf("\n");
	printf("R_inv perms\n");
	for(i = 0; i < 25; ++i)
	{
		printf("R_inv[%2d] = ", i);
		for(j = 0; j < 20; ++j)
		{
			printf("%c", twenty[R_inv[i][j]]);
//			printf("%d ", R_inv[i][j]);
		}
		printf("\n");
	}
	printf("\n");

	printf("input plugboard = ");
	for(j = 0; j < 26; ++j)
	{
		printf("%c", letter[inPlug[j]]);
	}
	printf("\n");

	printf("input plugboard inverse = ");
	for(j = 0; j < 26; ++j)
	{
		printf("%c", letter[inPlug_inv[j]]);
	}
	printf("\n");
	
	printf("output plugboard = ");
	for(j = 0; j < 26; ++j)
	{
		printf("%c", letter[outPlug[j]]);
	}
	printf("\n");

	printf("output plugboard inverse = ");
	for(j = 0; j < 26; ++j)
	{
		printf("%c", letter[outPlug_inv[j]]);
	}
	printf("\n");

	printf("split = ");
	for(j = 0; j < 26; ++j)
	{
		printf("%c", letter[split[j]]);
	}
	printf("\n");

	printf("unsplit = ");
	for(j = 0; j < 26; ++j)
	{
		printf("%c", letter[unsplit[j]]);
	}
	printf("\n\n");

#endif

#ifdef PR_KEY
	printf("\nKey:\n");
	printf("initial switch positions (S,L,M,R) = (%d,%d,%d,%d)\n", init_S, init_L, init_M, init_R);
	printf("motion (fast,medium,slow) = ");
	if(fast == 0 && medium == 1 && slow == 2)
	{
		printf("LMR");
	}
	if(fast == 0 && medium == 2 && slow == 1)
	{
		printf("LRM");
	}
	if(fast == 1 && medium == 0 && slow == 2)
	{
		printf("MLR");
	}
	if(fast == 1 && medium == 2 && slow == 0)
	{
		printf("MRL");
	}
	if(fast == 2 && medium == 0 && slow == 1)
	{
		printf("RLM");
	}
	if(fast == 2 && medium == 1 && slow == 0)
	{
		printf("RML");
	}
	printf("\n");
	printf("input plugboard inverse:\n");
	printf("ABCDEFGHIJKLMNOPQRSTUVWXYZ ---> ");
	for(i = 0; i < 26; ++i)
	{
		printf("%c", (char)(inPlug_inv[i] + 65));
	}
	printf("\n");
	printf("output plugboard inverse:\n");
	printf("ABCDEFGHIJKLMNOPQRSTUVWXYZ ---> ");
	for(i = 0; i < 26; ++i)
	{
		printf("%c", (char)(outPlug_inv[i] + 65));
	}
	printf("\n\nOutput:\n");
#endif

	cur_S = init_S;
	cur[0] = init_L;// left
	cur[1] = init_M;// middle
	cur[2] = init_R;// right
	
	//
	// Purple cipher
	//
	while(1)
	{
		temp = fgetc(in);
		if(temp == EOF)
		{
			break;
		}
		temp -= 65;
		if(temp < 0 || temp > 25)
		{
			fprintf(stderr, "\nError --- all input characters must be upper case A thru Z\n");
			exit(0);
		}
		
		inChar = (unsigned char)temp;

#ifdef PR_STEPS
		printf("inChar = %c\n", letter[inChar]);
#endif

		// Purple transformation
		if(flag == 0)// encryption
		{
			temp = split[inPlug[inChar]];
			if(temp >= 20)// a six
			{
				outChar = outPlug_inv[unsplit[S[cur_S][temp - 20]]];
			}
			else// a twenty
			{
				outChar = outPlug_inv[unsplit[R[cur[2]][M[cur[1]][L[cur[0]][temp]]]]];
			}
#ifdef PR_STEPS
			temp = inPlug[inChar];
			printf("inPlug = %c (%d)\n", letter[temp], temp);
			temp = split[temp];
			printf("split = %c (%d)\n", letter[unsplit[temp]], temp);			
			if(temp >= 20)// a six
			{
				temp = S[cur_S][temp - 20];
				printf("S = %c (%d)\n", letter[unsplit[temp]], temp);
				temp = unsplit[temp];
				printf("unsplit = %c (%d)\n", letter[temp], temp);
				temp = outPlug_inv[temp];
				printf("outPlug_inv = %c (%d)\n", letter[temp], temp);
			}
			else// a twenty
			{
				temp = L[cur[0]][temp];
				printf("L = %c (%d)\n", letter[unsplit[temp]], temp);
				temp = M[cur[1]][temp];
				printf("M = %c (%d)\n", letter[unsplit[temp]], temp);
				temp = R[cur[2]][temp];
				printf("R = %c (%d)\n", letter[unsplit[temp]], temp);
				temp = unsplit[temp];
				printf("unsplit = %c (%d)\n", letter[temp], temp);
				temp = outPlug_inv[temp];
				printf("outPlug_inv = %c (%d)\n", letter[temp], temp);
			}
#endif
		}
		else// decryption
		{
			temp = split[outPlug[inChar]];
			if(temp >= 20)// a six
			{
				outChar = inPlug_inv[unsplit[S_inv[cur_S][temp - 20]]];
			}
			else// a twenty
			{
				outChar = inPlug_inv[unsplit[L_inv[cur[0]][M_inv[cur[1]][R_inv[cur[2]][temp]]]]];
			}
#ifdef PR_STEPS
			temp = outPlug[inChar];
			printf("outPlug = %c (%d)\n", letter[temp], temp);
			temp = split[temp];
			printf("split = %c (%d)\n", letter[unsplit[temp]], temp);
			if(temp >= 20)// a six
			{
				temp = S_inv[cur_S][temp - 20];
				printf("S_inv = %c (%d)\n", letter[unsplit[temp]], temp);
				temp = unsplit[temp];
				printf("unsplit = %c (%d)\n", letter[temp], temp);
				temp = inPlug_inv[temp];
				printf("inPlug_inv = %c (%d)\n", letter[temp], temp);
			}
			else// a twenty
			{
				temp = R_inv[cur[2]][temp];
				printf("R_inv = %c (%d)\n", letter[unsplit[temp]], temp);
				temp = M_inv[cur[1]][temp];
				printf("M_inv = %c (%d)\n", letter[unsplit[temp]], temp);
				temp = L_inv[cur[0]][temp];
				printf("L_inv = %c (%d)\n", letter[unsplit[temp]], temp);
				temp = unsplit[temp];
				printf("unsplit = %c (%d)\n", letter[temp], temp);
				temp = inPlug_inv[temp];
				printf("inPlug_inv = %c (%d)\n", letter[temp], temp);
			}
#endif
		
		}// end if

#ifdef PR_STEPS
		printf("letter[temp] = %c, letter[outChar] = %c\n", letter[temp], letter[outChar]);
#endif

#ifdef PR_STEPS
		printf("outChar = ");
#endif

		printf("%c", letter[outChar]);
		
#ifdef PR_STEPS
		printf("\n");
#endif

		// S always steps
		// exactly one of the L,M,R switches step
		// Note that switches step _after_ encryption/decryption		
		if(cur_S == 24)// the medium switch steps
		{
			cur[medium] = stepSwitch(cur[medium], 25);
		}
		else
		{
			if(cur_S == 23 && cur[medium] == 24)// slow step
			{
				cur[slow] = stepSwitch(cur[slow], 25);
				
			}
			else// step fast switch
			{
				cur[fast] = stepSwitch(cur[fast], 25);
			
			}// end if

		}// end if
		
		// step sixes switch S --- always steps
		cur_S = stepSwitch(cur_S, 25);
#ifdef PR_STEPS
		printf("(cur_S,sur_L,cur_M,cur_R) = (%d,%d,%d,%d)\n", cur_S, cur[0], cur[1], cur[2]);
#endif
	
	}// end while

	printf("\n\n");

}// end main


void getInversePerm(int invPerm[], int perm[], int n)
{
	int i;
  
	for(i = 0; i < n; ++i)
	{
		invPerm[perm[i]] = i;

	}// next i

}// end getInversePerm


int stepSwitch(int a, int b)
{
	int t;
	t = a + 1;
	if(t >= b)
	{
		t = 0;
	}
	return(t);

}// end stepSwitch
