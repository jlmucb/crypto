
// deslib.h

// ----------------------------------------------------------------------- 


typedef unsigned char byte;

extern byte ip[64];
extern byte ipi[64];
extern byte P[32];
extern byte eb[48];
extern byte s[512];
extern byte pc1[64];
extern byte pc2[48];
extern int krot[16];

void printmat(byte [], int, int, int);
void prbit(char* , byte* [], int , int);
int permute(byte [], byte [], int, int);
int invert(byte [], byte [], int);
void tobits(int, byte []);
void frbits(byte [], int*);
void sub(byte [], byte [], int );
void f(int, byte [], byte[]);
void compkeys(int [2]);
int dotint(int, int);
int des(int*, int*, int);

#include "stdio.h"


// ----------------------------------------------------------------------- 
