#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
 
// print output to terminal 
#define PR_OUTPUT

char decrypt (char input);
char encrypt (char input);
void encryptFromFile ();
void generateCipherOffsets();
void generateControlOffsets();
void generateIndexOffsets();
void init ();
void loadConf ();
char pathThroughCipherRotorsL2R (char input);
char pathThroughCipherRotorsR2L (char input);
char pathThroughControlRotorsR2L (char input);
int pathThroughIndexRotorsL2R (int input);
void printConf ();
void printOffsets ();
void printCipherOffsets();
void printControlOffsets();
void printControlOffsetsTemp();
void printControlOffsetsPhase2();
void reverse (int index);
void setPosition (int rotor, char pos);
void simulator (char cipherInit[],
			    char controlInit[],
 			    char indexInit[],
			    char cipherOrder[],
			    char controlOrder[],
			    char indexOrder[],
			    char cipherOrient[],
			    char controlOrient[],
			    int direction);
void stepOffsets (int rotor);


FILE *in,
	 *out;
	  
int stepCount[5] = {0,0,0,0,0};
const int ENCRYPT = 0;	// Encryption mode
const int DECRYPT = 1;	// Decryption mode
const char* INDEX_ROTORS[5] = {"7591482630" , "3810592764", "4086153297",
								"3980526174", "6497135280"};
const char* CIPHER_AND_CONTROL_ROTORS[10] = {"YCHLQSUGBDIXNZKERPVJTAWFOM",
											"INPXBWETGUYSAOCHVLDMQKZJFR",
											"WNDRIOZPTAXHFJYQBMSVEKUCGL",
											"TZGHOBKRVUXLQDMPNFWCJYEIAS",
											"YWTAHRQJVLCEXUNGBIPZMSDFOK",
					 						"QSLRBTEKOGAICFWYVMHJNXZUDP",
											"CHJDQIGNBSAKVTUOXFWLEPRMZY",
											"CDFAJXTIMNBEQHSUGRYLWZKVPO",
											"XHFESZDNRBCGKQIJLTVMUOYAPW",
											"EZJQXMOGYTCSFRIUPVNADLHWBK"};


char *CipherRotors[5];	// 2D array that represents the initial cipher rotors
char *ControlRotors[5];	// 2D array that represents the initial control rotors
char *IndexRotors[5];	// 2D array that represents the initial index rotors
char RotorPosition[15] = "AAAAAAAAAA00000";

int *CipherRotorsOffsets[5];	// 2D array that represents the current
								// cipher rotor offsets

int *ControlRotorsOffsets[5];	// 2D array that reprensents tha current
								// control rotor offsets

int *IndexRotorsOffsets[5];		// 2D array that represents the current
								// index rotor offsets
int RotorOrientations[15];		// 2d array to represents if a rotor is in
								// the normal position [0] or backwards [1]
int StepArray[3] = {0, 0, 0};	// Offset from 'A' for the stepping
								// control rotors

int cipherStepCount[5] = {0,0,0,0,0};

/* Decrypt a letter */
char decrypt (char input)
{
	/* Active output of the control rotors */
	char controlOutput[5] = {'F', 'G', 'H', 'I', 0};
	/* Active input of the index rotors */
	int indexInput[10] = {0,0,0,0,0,0,0,0,0,0};
	int x, count;
	char output;

	/* Generate the output of the control rotors */
	for (x=0;x<4;x++)
	{
		controlOutput[x] = pathThroughControlRotorsR2L(controlOutput[x]);
	}

	/* Generate the active inputs to the index rotors based on the
	 * output of the control rotors
	 */
	for (x=0;x<4;x++)
	{
		if (controlOutput[x] == 'B')
		{
			indexInput[1] = 1;
		}else if (controlOutput[x] == 'C')
		{
			indexInput[2] = 1;
		}else if (controlOutput[x] >= 'D' && controlOutput[x] <= 'E')
		{
			indexInput[3] = 1;
		}else if (controlOutput[x] >= 'F' && controlOutput[x] <= 'H')
		{
			indexInput[4] = 1;
		}else if (controlOutput[x] >= 'I' && controlOutput[x] <= 'K')
		{
			indexInput[5] = 1;
		}else if (controlOutput[x] >= 'L' && controlOutput[x] <= 'O')
		{
			indexInput[6] = 1;
		}else if (controlOutput[x] >= 'P' && controlOutput[x] <= 'T')
		{
			indexInput[7] = 1;
		}else if (controlOutput[x] >= 'U' && controlOutput[x] <= 'Z')
		{
			indexInput[8] = 1;
		}else if (controlOutput[x] == 'A')
		{
			indexInput[9] = 1;
		}
	}

	count = 0;

	/* Count the number of active inputs to the index rotors */
	for (x=0;x<10;x++)
	{
		if (indexInput[x] == 1)
			count++;
	}

	/* Active output of the index rotors */
	int *inputOutput = calloc(count, sizeof(int));
	count = 0;

	/* Generate the output of the index rotors */
	for (x=0;x<10;x++)
	{
		if (indexInput[x] == 1)
		{
			inputOutput[count] = pathThroughIndexRotorsL2R(x);
			count++;
		}
	}

	/* Decrypt the input */
	output = pathThroughCipherRotorsR2L(input);

	int *stepping = calloc(5, sizeof(int));

	/* Determine which cipher rotor steps */
	for (x=0;x<count;x++)
	{
		if (inputOutput[x] == 1 || inputOutput[x] == 2)
		{
			stepping[4] = 1;
		}else if (inputOutput[x] == 3 || inputOutput[x] == 4)
		{
			stepping[3] = 1;
		}else if (inputOutput[x] == 5 || inputOutput[x] == 6)
		{
			stepping[2] = 1;
		}else if (inputOutput[x] == 7 || inputOutput[x] == 8)
		{
			stepping[1] = 1;
		}else if (inputOutput[x] == 9 || inputOutput[x] == 0)
		{
			stepping[0] = 1;
		}
	}

	/* Step the cipher rotors */
	for (x=0;x<5;x++)
	{
		if (stepping[x] == 1)
		{
			stepOffsets(x);
		}
	}

	/* Step the fast control rotor */
	stepOffsets(7);
	StepArray[1] = (StepArray[1] - 1 + 26) % 26;

	/* If the fast control rotor reaches 'O', step the medium control rotor */
	if (StepArray[1] + 'A' + 1 == 'O')
	{
		stepOffsets(8);
		StepArray[2] = (StepArray[2] - 1 + 26) % 26;

		/* If the medium rotor reaches 'O', step the slow control rotor */
		if (StepArray[2] + 'A' + 1 == 'O')
		{
			stepOffsets(6);
			StepArray[0] = (StepArray[0] - 1 + 26) % 26;
		}
	}

	return output;

}

/* Encrypt a letter */
char encrypt (char input)
{
	/* Active output of the control rotors */
	char controlOutput[5] = {'F', 'G', 'H', 'I', 0};
	/* Active input of the index rotors */
	int indexInput[10] = {0,0,0,0,0,0,0,0,0,0};
	int x, count;
	char output;

	/* Generate the output of the control rotors */
	for (x=0;x<4;x++)
	{
		controlOutput[x] = pathThroughControlRotorsR2L(controlOutput[x]);
	}

	/* Generate the active inputs to the index rotors based on the
	 * output of the control rotors
	 */
	for (x=0;x<4;x++)
	{
		if (controlOutput[x] == 'B')
		{
			indexInput[1] = 1;
		}else if (controlOutput[x] == 'C')
		{
			indexInput[2] = 1;
		}else if (controlOutput[x] >= 'D' && controlOutput[x] <= 'E')
		{
			indexInput[3] = 1;
		}else if (controlOutput[x] >= 'F' && controlOutput[x] <= 'H')
		{
			indexInput[4] = 1;
		}else if (controlOutput[x] >= 'I' && controlOutput[x] <= 'K')
		{
			indexInput[5] = 1;
		}else if (controlOutput[x] >= 'L' && controlOutput[x] <= 'O')
		{
			indexInput[6] = 1;
		}else if (controlOutput[x] >= 'P' && controlOutput[x] <= 'T')
		{
			indexInput[7] = 1;
		}else if (controlOutput[x] >= 'U' && controlOutput[x] <= 'Z')
		{
			indexInput[8] = 1;
		}else if (controlOutput[x] == 'A')
		{
			indexInput[9] = 1;
		}
	}

	count = 0;

	/* Count the number of active inputs to the index rotors */
	for (x=0;x<10;x++)
	{
		if (indexInput[x] == 1)
		{
			count++;
		}
	}

	/* Active output of the index rotors */
	int *inputOutput = calloc(count, sizeof(int));
	count = 0;

	/* Generate the output of the index rotors */
	for (x=0;x<10;x++)
	{
		if (indexInput[x] == 1)
		{
			inputOutput[count] = pathThroughIndexRotorsL2R(x);
			count++;
		}
	}

	/* Encrypt the input */
	output = pathThroughCipherRotorsL2R(input);

	int *stepping = calloc(5, sizeof(int));

	/* Determine which cipher rotor steps */
	for (x=0;x<count;x++)
	{
		if (inputOutput[x] == 1 || inputOutput[x] == 2)
		{
			stepping[4] = 1;
		}else if (inputOutput[x] == 3 || inputOutput[x] == 4)
		{
			stepping[3] = 1;
		}else if (inputOutput[x] == 5 || inputOutput[x] == 6)
		{
			stepping[2] = 1;
		}else if (inputOutput[x] == 7 || inputOutput[x] == 8)
		{
			stepping[1] = 1;
		}else if (inputOutput[x] == 9 || inputOutput[x] == 0)
		{
			stepping[0] = 1;
		}
	}

	/* Step the cipher rotors */
	for (x=0;x<5;x++)
	{
		if (stepping[x] == 1)
		{
			stepCount[x]++;
			stepOffsets(x);
		}
	}

	/* Step the fast control rotor */
	stepOffsets(7);
	StepArray[1] = (StepArray[1] - 1 + 26) % 26;

	/* If the fast control rotor reaches 'O', step the medium control rotor */
	if (StepArray[1] + 'A' + 1 == 'O')
	{
		stepOffsets(8);
		StepArray[2] = (StepArray[2] - 1 + 26) % 26;

		/* If the medium rotor reaches 'O', step the slow control rotor */
		if (StepArray[2] + 'A' + 1 == 'O')
		{
			stepOffsets(6);
			StepArray[0] = (StepArray[0] - 1 + 26) % 26;
		}
	}

	return output;
}

void encryptFromFile ()
{
	int row = 0;
	int count = 0;
	int x;

	char input[300] = "\n";

	printf("Enter input file: ");
	fgets(input, sizeof(input), stdin);

	input[strlen(input)-1] = 0;

	FILE *inputFile = fopen(input, "r");

	if (inputFile == NULL)
	{
		printf("ERROR opening input file\n");
	}

	while (feof(inputFile) == 0)
	{
		fgets(input, sizeof(input), inputFile);
		row++;
		char c = 0;

		for (x=0;x<strlen(input);x++)
		{
			if (toupper(input[x]) == 'Z')
			{
				c = encrypt('X');
			}else if (input[x] == ' ')
			{
				c = encrypt('Z');
			}else if (toupper(input[x]) >= 65 &&
				toupper(input[x]) <= 90)
			{
				c = encrypt(toupper(input[x]));
			}

			count++;

			printf("%c", c);
		}

		printf("\n");
	}

	fclose(inputFile);

}

void generateCipherOffsets ()
{
	int x, y;

	/* Generate the offsets for the cipher and control rotors */
	for (x=0;x<5;x++)
	{
		for (y=0;y<26;y++)
		{
			CipherRotorsOffsets[x][y] = (CipherRotors[x][y] - 'A' - y) % 26;
			if (CipherRotorsOffsets[x][y] < 0)
				CipherRotorsOffsets[x][y] += 26;
		}
	}
}

void generateControlOffsets ()
{
	int x, y;

	/* Generate the offsets for the control rotors */
	for (x=0;x<5;x++)
	{
		for (y=0;y<26;y++)
		{
			ControlRotorsOffsets[x][y] = (ControlRotors[x][y] - 'A' - y) % 26;
			if (ControlRotorsOffsets[x][y] < 0)
				ControlRotorsOffsets[x][y] += 26;
		}
	}
}

void generateIndexOffsets ()
{
	int x, y;

	for (x=0;x<5;x++)
	{
		for (y=0;y<10;y++)
		{
			IndexRotorsOffsets[x][y] = (IndexRotors[x][y] - '0' - y) % 10;
			if (IndexRotorsOffsets[x][y] < 0)
				IndexRotorsOffsets[x][y] += 10;
		}
	}
}

/* Initialize rotor arrays */
void init ()
{
	int x;

	/* Allocate space for all arrays representing rotors and their offsets */
	for (x=0;x<5;x++)
	{
		CipherRotors[x] = calloc(27, sizeof(char));
		ControlRotors[x] = calloc(27, sizeof(char));
		IndexRotors[x] = calloc(11, sizeof(char));
		CipherRotorsOffsets[x] = calloc(27, sizeof(int));
		ControlRotorsOffsets[x] = calloc(27, sizeof(int));
		IndexRotorsOffsets[x] = calloc(11, sizeof(int));
	}

	/* Sets all the rotors to the forward position */
	for (x=0;x<15;x++)
	{
		RotorOrientations[x] = 0;
	}

	/* Set initial values for the stepping array */
	for (x=0;x<3;x++)
	{
		StepArray[x] = 0;
	}

	/* Set the current permutation of the rotors */
	for (x=0;x<5;x++)
	{
		strcpy(CipherRotors[x], CIPHER_AND_CONTROL_ROTORS[x]);
		strcpy(ControlRotors[x], CIPHER_AND_CONTROL_ROTORS[x+5]);
		strcpy(IndexRotors[x], INDEX_ROTORS[x]);
	}

	strcpy(RotorPosition, "AAAAAAAAAA00000");
	StepArray[0] = 0;
	StepArray[1] = 0;
	StepArray[2] = 0;

	generateCipherOffsets();
	generateControlOffsets();
	generateIndexOffsets();
}

/* Follows a path through the cipher rotor bank given an input.
 * The path will be following a left to right direction.
 * This is used during encryption mode only
 */
char pathThroughCipherRotorsL2R (char input)
{
	char output = input;
	int x, pos, newPos;

	/* Generate the path through the cipher rotors */
	for (x=0;x<5;x++)
	{
		pos = output - 'A';
		newPos = (pos + CipherRotorsOffsets[x][pos])%26;
		output = newPos + 'A';
	}

	return output;
}

/* Follows a path through the cipher rotor bank given an input.
 * The path will be following a right to left direction.
 * This is used during decryption mode only
 */
char pathThroughCipherRotorsR2L (char input)
{
	int x, y, newPos;
	char output = input;

	/*
	 * Generate the path through cipher rotors 4 to 0
	 */
	for (x=4;x>=0;x--)
	{
		for (y=0;y<26;y++)
		{
			if ((y + CipherRotorsOffsets[x][y]) % 26 ==
				output - 'A')
			{
				newPos = y;
				y = 27;
			}
		}
		output = 'A' + newPos;
	}

	return output;
}

/* Follows a path through the control rotor bank given an input.
 * The path will be following a right to left direction.
 * This is used during both encryption and decryption mode.
 */
char pathThroughControlRotorsR2L (char input)
{
	int x, y, newPos;
	char output = input;

	/*
	 * Generate the path through control rotors 4 to 0
	 */
	for (x=4;x>=0;x--)
	{
		for (y=0;y<26;y++)
		{
			if ((y + ControlRotorsOffsets[x][y]) % 26 ==
				output - 'A')
			{
				newPos = y;
				y = 27;
			}
		}
		output = 'A' + newPos;
	}

	return output;
}

/* Follows a path through the index rotor bank given an input.
 * The path will be following a left to right direction.
 * This is used during both encryption and decryption mode.
 */
int pathThroughIndexRotorsL2R (int input)
{
	int x;
	int output = input;

	for (x=0;x<5;x++)
	{
		output = (output + IndexRotorsOffsets[x][output]) % 10;
	}

	return output;
}

/* Print the initial configuration */
void printConf ()
{
	printf("1st Cipher Rotor: \t%s\n", CipherRotors[0]);
	printf("2nd Cipher Rotor: \t%s\n", CipherRotors[1]);
	printf("3rd Cipher Rotor: \t%s\n", CipherRotors[2]);
	printf("4th Cipher Rotor: \t%s\n", CipherRotors[3]);
	printf("5th Cipher Rotor: \t%s\n\n", CipherRotors[4]);

	printf("1st Control Rotor: \t%s\n", ControlRotors[0]);
	printf("2nd Control Rotor: \t%s\n", ControlRotors[1]);
	printf("3rd Control Rotor: \t%s\n", ControlRotors[2]);
	printf("4th Control Rotor: \t%s\n", ControlRotors[3]);
	printf("5th Control Rotor: \t%s\n\n", ControlRotors[4]);

	printf("1st Index Rotor: \t%s\n", IndexRotors[0]);
	printf("2nd Index Rotor: \t%s\n", IndexRotors[1]);
	printf("3rd Index Rotor: \t%s\n", IndexRotors[2]);
	printf("4th Index Rotor: \t%s\n", IndexRotors[3]);
	printf("5th Index Rotor: \t%s\n\n", IndexRotors[4]);

}

/* Print the current offsets */
void printOffsets ()
{
	int x, y;

	printf("Cipher rotors\n");

	for (x=0;x<5;x++)
	{
		for (y=0;y<26;y++)
		{
			printf("%i ", CipherRotorsOffsets[x][y]);
		}
		printf("\n");
	}

	printf("Control rotors\n");

	for (x=0;x<5;x++)
	{
		for (y=0;y<26;y++)
		{
			printf("%i ", ControlRotorsOffsets[x][y]);
		}
		printf("\n");
	}

	printf("Index rotors\n");

	for (x=0;x<5;x++)
	{
		for (y=0;y<10;y++)
		{
			printf("%i ", IndexRotorsOffsets[x][y]);
		}

		printf("\n");
	}
}

/* Print the current offsets */
void printCipherOffsets ()
{
	int x, y;

	printf("Cipher rotors\n");

	for (x=0;x<5;x++)
	{
		for (y=0;y<26;y++)
		{
			printf("%i ", CipherRotorsOffsets[x][y]);
		}
		printf("\n");
	}
}

/* Print the current control offsets */
void printControlOffsets()
{
	int x, y;
	printf("Control rotors\n");

	for (x=0;x<5;x++)
	{
		for (y=0;y<26;y++)
		{
			printf("%i ", ControlRotorsOffsets[x][y]);
		}
		printf("\n");
	}
}

void printPosition ()
{
	int x;

	printf("Positions: ");

	for (x=0;x<15;x++)
	{
		printf("%c ", RotorPosition[x]);
	}

	printf("\n");
}

/* Reverses a rotor */
void reverse (int index)
{
	int x, setIndex, cipher;
	char *newRotor;

	if (index <10)
	{
		if (index < 5)
		{
			setIndex = index;
			cipher = 1;
		}
		else if (index >= 5)
		{
			setIndex = index - 5;
			cipher = 0;
		}

		newRotor = calloc(27, sizeof(char));

		for (x=0;x<26;x++)
		{
			if (cipher == 1)
			{
				newRotor[(x + CipherRotorsOffsets[setIndex][x]) % 26]
					= x + 'A';
			}else if (cipher == 0)
			{
				newRotor[(x + ControlRotorsOffsets[setIndex][x]) % 26]
					= x + 'A';
			}
		}

		for (x=0;x<26;x++)
		{
			if (cipher == 1)
			{
				CipherRotors[setIndex][x] = newRotor[x];
			}else if (cipher == 0)
			{
				ControlRotors[setIndex][x] = newRotor[x];
			}
		}

		if (cipher == 1)
			generateCipherOffsets();
		else if (cipher == 0)
			generateControlOffsets();
	}else if (index >= 10)
	{
		setIndex = index - 10;

		newRotor = calloc(11, sizeof(char));

		for (x=0;x<10;x++)
		{
			newRotor[IndexRotors[setIndex][x] - '0'] = x + '0';
		}

		for (x=0;x<10;x++)
		{
			IndexRotors[setIndex][x] = newRotor[x];
		}

		generateIndexOffsets();
	}

	if (RotorOrientations[index] == 0)
		RotorOrientations[index] = 1;
	else
		RotorOrientations[index] = 0;

	free(newRotor);
}

void setPosition (int rotor, char pos)
{
	while (RotorPosition[rotor] != pos)
		stepOffsets(rotor);
}

/* Step the offsets for a rotor */
void stepOffsets (int rotor)
{
	int *copy = calloc(27, sizeof(int));
	int x;

	if (rotor < 10)
	{
		if (rotor < 5)
		{
			/* Make a copy of the rotor offsets */
			for (x=0;x<27;x++)
			{
				copy[x] = CipherRotorsOffsets[rotor][x];
			}

			if (RotorOrientations[rotor] == 0)
			{
				/* Shift the offsets by 1 */
				CipherRotorsOffsets[rotor][0] = copy[25];

				for (x=1;x<26;x++)
				{
					CipherRotorsOffsets[rotor][x] = copy[x-1];
				}
			}else if (RotorOrientations[rotor] == 1)
			{
				/* Shift the offsets by -1 */
				CipherRotorsOffsets[rotor][25] = copy[0];

				for (x=0;x<25;x++)
				{
					CipherRotorsOffsets[rotor][x] = copy[x+1];
				}
			}
		}else if (rotor >= 5)
		{
			/* Make a copy of the rotor offsets */
			for (x=0;x<27;x++)
			{
				copy[x] = ControlRotorsOffsets[rotor-5][x];
			}

			if (RotorOrientations[rotor] == 0)
			{
				/* Shift the offsets by 1 */
				ControlRotorsOffsets[rotor-5][0] = copy[25];

				for (x=1;x<26;x++)
				{
					ControlRotorsOffsets[rotor-5][x] = copy[x-1];
				}
			}else if (RotorOrientations[rotor] == 1)
			{
				/* Shift the offsets by -1 */
				ControlRotorsOffsets[rotor-5][25] = copy[0];

				for (x=0;x<25;x++)
				{
					ControlRotorsOffsets[rotor-5][x] = copy[x+1];
				}
			}
		}

		if (RotorOrientations[rotor] == 0)
		{
			if (RotorPosition[rotor] == 'A')
				RotorPosition[rotor] = 'Z';
			else
				RotorPosition[rotor] = RotorPosition[rotor] - 1;
		}else if (RotorOrientations[rotor] == 1)
		{
			if (RotorPosition[rotor] == 'Z')
				RotorPosition[rotor] = 'A';
			else
				RotorPosition[rotor] = RotorPosition[rotor] + 1;
		}
	}else if (rotor >= 10)
	{
		if (RotorOrientations[rotor] == 0)
		{
			for (x=0;x<10;x++)
			{
				copy[x] = IndexRotorsOffsets[rotor-10][x];
			}

			IndexRotorsOffsets[rotor-10][9] = copy[0];

			for (x=0;x<9;x++)
			{
				IndexRotorsOffsets[rotor-10][x] = copy[x+1];
			}
		}else if (RotorOrientations[rotor] == 1)
		{
			for (x=0;x<10;x++)
			{
				copy[x] = IndexRotorsOffsets[rotor-10][x];
			}

			IndexRotorsOffsets[rotor-10][0] = copy[9];

			for (x=1;x<10;x++)
			{
				IndexRotorsOffsets[rotor-10][x] = copy[x-1];
			}
		}

		if (RotorOrientations[rotor] == 0)
		{
			if (RotorPosition[rotor] == '9')
				RotorPosition[rotor] = '0';
			else
				RotorPosition[rotor] = RotorPosition[rotor] + 1;
		}else if (RotorOrientations[rotor] == 1)
		{
			if (RotorPosition[rotor] == '0')
				RotorPosition[rotor] = '9';
			else
				RotorPosition[rotor] = RotorPosition[rotor] - 1;
		}
	}

	free(copy);
}

/*
 * Driver for the SIGABA simulator
 *
 * Supports two modes: Encryption and Decryption (of course!)
 *
 * Encryption mode:
 * Take a string of input and pass each character to encrypt().
 * Take the return value and output.
 * If Z is input, actually encrypt X.
 * If ' ' (space) is input, actually encrypt Z
 *
 * Decryption mode:
 * If Z is input, output is a space
 *
 */
void simulator (char cipherInit[],
			    char controlInit[],
 			    char indexInit[],
			    char cipherOrder[],
			    char controlOrder[],
			    char indexOrder[],
			    char cipherOrient[],
			    char controlOrient[],
			    int direction)
{
	int a, x, pos;
	char plaintext;
	char ciphertext;

	// place rotors in the correct order
	for (x = 0; x < 5; x++)
	{
		strcpy(CipherRotors[x], CIPHER_AND_CONTROL_ROTORS[cipherOrder[x]-'0']);
	}
		
	for (x = 0; x < 5; x++)
	{
		strcpy(ControlRotors[x], CIPHER_AND_CONTROL_ROTORS[controlOrder[x]-'0']);
	}

	for (x = 0; x < 5; x++)
	{
		strcpy(IndexRotors[x], INDEX_ROTORS[indexOrder[x]-'0']);
	}

	strcpy(RotorPosition, "AAAAAAAAAA00000");
	StepArray[0] = 0;
	StepArray[1] = 0;
	StepArray[2] = 0;

	generateCipherOffsets();
	generateControlOffsets();
	generateIndexOffsets();

	// set initial positions of cipher/control/index rotors
	for (x = 0; x < 5; x++)
	{
		setPosition(x, cipherInit[x]);
	}
	for (x = 0; x < 5; x++)
	{
		setPosition(x + 5, controlInit[x]);
	}
	for (x = 0; x < 5; x++)
	{
		setPosition(x + 10, indexInit[x]);
	}

	// set orientation of cipher/control rotors
	for (x = 0; x < 5; x++)
	{
		if(cipherOrient[x] - '1' == 0)
		{
			reverse(x);
		}
	}
	for (x = 0; x < 5; x++)
	{
		if(controlOrient[x] - '1' == 0)
		{
			reverse(x + 5);
		}
	}

	//
	// encryption or decryption
	//
	if(direction == 0)// encrypt
	{
		pos = 0;

		// During encryption, if input is Z,
		//	X is sent as input to encrypt()
		// During encryption, if input is a space,
		//	Z is sent as input to encrypt();

		while(1)
		{
			a = fscanf(in, "%c", &plaintext);
			if(a != 1)
			{
				break;
			}
			if (toupper(plaintext) == 'Z')
			{
				ciphertext = encrypt('X');
			}
			else if (plaintext == ' ')
			{
				ciphertext = encrypt('Z');
			}
			else if (toupper(plaintext) >= 65 && toupper(plaintext) <= 90)
			{
				ciphertext = encrypt(toupper(plaintext));
			}
#ifdef PR_OUTPUT
			printf("%c", ciphertext);
#endif
			fprintf(out, "%c", ciphertext);
			
		}// end while
		
	}
	else// decrypt
	{
		// During decryption, if the decrypted letter is Z,
		// a space is sent to the output
		while(1)
		{
			a = fscanf(in, "%c", &ciphertext);
			if(a != 1)
			{
				break;
			}

			if (toupper(ciphertext) >= 65 && toupper(ciphertext) <= 90)
			{
				plaintext = decrypt(toupper(ciphertext));

				if (plaintext - 'Z' == 0)
				{
					plaintext = ' ';
				}
			}
#ifdef PR_OUTPUT
			printf("%c", plaintext);
#endif
			fprintf(out, "%c", plaintext);
			
		}// end while

	}// end if(direction == 0)

#ifdef PR_OUTPUT
	printf("\n");
#endif

}// end simulator


int main (int argc, const char *argv[])
{
	char cipherInit[5],
		 controlInit[5],
		 indexInit[5],
		 cipherOrder[5],
		 controlOrder[5],
		 indexOrder[5],
		 cipherOrient[5],
		 controlOrient[5],
		 infname[128],
		 outfname[128];

	int i,
		t,
		cnt[10],
		direction;

	init();

	if(argc != 7)
	{
oops:   fprintf(stderr, "\n\nUsage: %s rotorOrder orientation initPos direction ", argv[0]);
		fprintf(stderr, "infile outfile\n\n");
		fprintf(stderr, "where rotorOrder == order of cipher/cotrol rotors and order of ");
		fprintf(stderr, "index rotors\n");
		fprintf(stderr, "                    (perm of 0-9 and perm of 0-4, no spaces)\n");
		fprintf(stderr, "      orientation == cipher/control rotor orientations,\n");
		fprintf(stderr, "                0 = forward, 1 = reverse (binary 10-tuple)\n");
		fprintf(stderr, "      initPos == initial positions for cipher/control/index rotors\n");
		fprintf(stderr, "                 (10-tuple of A thru Z, 5-tuple of 0 thru 9)\n");
		fprintf(stderr, "      direction == 0 for encrypt, 1 for decrypt\n");
		fprintf(stderr, "      infile == input file name\n");
		fprintf(stderr, "      outfile == output file name\n\n");
		fprintf(stderr, "For example:\n\n%s 987654321043210 0000000011 ABCDEFGHIJ98765", argv[0]);
		fprintf(stderr, " 0 plain.txt cipher.txt\n\n");
		exit(0);
	}

	if(strlen(argv[1]) != 15)
	{
		fprintf(stderr, "\nError --- must specify order of 15 rotors\n");
		goto oops;
	}
	
	strncpy(cipherOrder, argv[1], 5);
	for(i = 0; i < 10; ++i)
	{
		cnt[i] = 0;
	}
	for(i = 0; i < 5; ++i)
	{
		t = cipherOrder[i] - '0'; 
		if(t < 0 || t > 9)
		{
			fprintf(stderr, "\nError --- each cipher rotor order must be between 0 and 9\n");
			goto oops;
		}
		++cnt[t];
	}
	
	strncpy(controlOrder, &argv[1][5], 5);
	for(i = 0; i < 5; ++i)
	{
		t = controlOrder[i] - '0'; 
		if(t < 0 || t > 9)
		{
			fprintf(stderr, "\nError --- each control rotor order must be between 0 and 9\n");
			goto oops;
		}
		++cnt[t];
	}
	for(i = 0; i < 10; ++i)
	{
		if(cnt[i] != 1)
		{
			fprintf(stderr, "\nError --- cipher/control rotors must be perm of 0 thru 9\n");
			goto oops;		
		}
	}
	
	strncpy(indexOrder, &argv[1][10], 5);
	for(i = 0; i < 5; ++i)
	{
		cnt[i] = 0;
	}
	for(i = 0; i < 5; ++i)
	{
		t = indexOrder[i] - '0'; 
		if(t < 0 || t > 9)
		{
			fprintf(stderr, "\nError --- each index rotor order must be between 0 and 4\n");
			goto oops;
		}
		++cnt[t];
	}
	for(i = 0; i < 5; ++i)
	{
		if(cnt[i] != 1)
		{
			fprintf(stderr, "\nError --- index rotors must be perm of 0 thru 4\n");
			goto oops;		
		}
	}

	strncpy(cipherOrient, argv[2], 5);
	for(i = 0; i < 5; ++i)
	{
		t = cipherOrient[i] - '0'; 
		if(t < 0 || t > 1)
		{
			fprintf(stderr, "\nError --- each cipher rotor orientation must be 0 or 1\n");
			goto oops;
		}
	}

	strncpy(controlOrient, &argv[2][5], 5);
	for(i = 0; i < 5; ++i)
	{
		t = controlOrient[i] - '0'; 
		if(t < 0 || t > 1)
		{
			fprintf(stderr, "\nError --- each control rotor orientation must be 0 or 1\n");
			goto oops;
		}
	}

	strncpy(cipherInit, argv[3], 5);
	for(i = 0; i < 5; ++i)
	{
		t = cipherInit[i] - 'A'; 
		if(t < 0 || t > 25)
		{
			fprintf(stderr, "\nError --- each cipher rotor init must be A thru Z\n");
			goto oops;
		}
	}

	strncpy(controlInit, &argv[3][5], 5);
	for(i = 0; i < 5; ++i)
	{
		t = controlInit[i] - 'A'; 
		if(t < 0 || t > 25)
		{
			fprintf(stderr, "\nError --- each control rotor init must be A thru Z\n");
			goto oops;
		}
	}

	strncpy(indexInit, &argv[3][10], 5);
	for(i = 0; i < 5; ++i)
	{
		t = indexInit[i] - '0'; 
		if(t < 0 || t > 9)
		{
			fprintf(stderr, "\nError --- each index rotor init must be 0 thru 9\n");
			goto oops;
		}
	}

	direction = atoi(argv[4]);
	if(direction < 0 || direction > 1)
	{
		fprintf(stderr, "\nError --- direction must be 0 or 1\n");
		goto oops;
	}

	sprintf(infname, argv[5]);
	
    in = fopen(infname, "r");
    if(in == NULL)
    {
        fprintf(stderr, "\n\nError opening file %s\nTry again\n\n", infname);
        goto oops;
    }

	sprintf(outfname, argv[6]);

    out = fopen(outfname, "w");
    if(out == NULL)
    {
        fprintf(stderr, "\n\nError opening file %s\nTry again\n\n", outfname);
        goto oops;
    }

	simulator(cipherInit,
			  controlInit,
			  indexInit,
			  cipherOrder,
			  controlOrder,
			  indexOrder,
			  cipherOrient,
			  controlOrient,
			  direction);

	fclose(in);
	fclose(out);
	
	return 0;
}
