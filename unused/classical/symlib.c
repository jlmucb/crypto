// symlib.c
//		computations for des


/* -------------------------------------------------------------------- */

#include "symlib.h"

byte ip[64]= {
	58,50,42,34,26,18,10, 2,60,52,44,36,28,20,12, 4,
	62,54,46,38,30,22,14, 6,64,56,48,40,32,24,16, 8,
	57,49,41,33,25,17, 9, 1,59,51,43,35,27,19,11, 3,
	61,53,45,37,29,21,13, 5,63,55,47,39,31,23,15, 7};
byte ipi[64]= {
	40, 8,48,16,56,24,64,32,39, 7,47,15,55,23,63,31,
	38, 6,46,14,54,22,62,30,37, 5,45,13,53,21,61,29,
	36, 4,44,12,52,20,60,28,35, 3,43,11,51,19,59,27,
	34, 2,42,10,50,18,58,26,33, 1,41, 9,49,17,57,25};
byte P[32]= {
	16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
	 2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25};
byte eb[48]= {
	32, 1, 2, 3, 4, 5,
	 4, 5, 6, 7, 8, 9,
	 8, 9,10,11,12,13,
	12,13,14,15,16,17,
	16,17,18,19,20,21,
	20,21,22,23,24,25,
	24,25,26,27,28,29,
	28,29,30,31,32,1
	};

/*
 *	substitution boxes
 */

byte s[512]= {
	/* s1 */
	14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
	0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
	4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
	15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,
	/* s2 */
	15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
	3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
	0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
	13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,
	/* s3 */
	10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
	13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
	13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
	1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
	/* s4 */
	7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
	13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
	10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
	3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
	/* s5 */
	2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
	14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
	4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
	11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,
	/* s6 */
	12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
	10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
	9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
	4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
	/* s7 */
	4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
	13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
	1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
	6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
	/* s8 */
	13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
	1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
	7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
	2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11};


//	key selection permutations

byte pc1[64]= {
	57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,
	59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,
	31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,
	29,21,13,5,28,20,12,4,1,1,1,1,1,1,1,1};

byte pc2[48]= {
	14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
	26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
	51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};

int krot[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};


/* ----------------------------------------------------------------------- */


void printmat(byte bMat[], int iSize, int iLineSize, int iRadix)
{
	char* p8Fmt="%02o ";
	char* p10Fmt="%02d ";
	char* p16Fmt="%02x ";
	char* pstrFmt;
	int i;
	int iPrinted= 0;

	switch(iRadix) {
		default:
		case 10:
			pstrFmt= p10Fmt;
			break;
		case 8:
			pstrFmt= p8Fmt;
			break;
		case 16:
			pstrFmt= p16Fmt;
			break;
		}

	for(i= 0; i<iSize; i++) {
		printf(pstrFmt, (int)bMat[i]);
		if((++iPrinted)>=iLineSize) {
			iPrinted= 0;
			printf("\n");
			}
		}

	if(iPrinted>0)
		printf("\n");
	}


void prbit(char* pstrText, byte* mat[], int size, int iSizeBlock)

// pretty print block

{
	int i;

	printf("%s", pstrText);
	for(i=0;i<size;i++)
		if((i%iSizeBlock)==0)
			printf(" %d", mat[i]);
		else
			printf("%d", mat[i]);
	return;
	}



int permute(byte bits[], byte perm[], int n, int m)

{
	int i;
	byte tmp[64];

	for(i=0;i<m;i++)
		tmp[i]= bits[i];

	for(i=0;i<n;i++)
		bits[i]= tmp[perm[i]-1];
	return(1);
}


int invert(byte a[], byte b[], int n)

{
	int i,j;

	for(i=0;i<n;i++) {
		j= a[i];
		b[j-1]= i+1;
		}
	return(1);
	}


void tobits(int in, byte out[])

{
	int i;

	for(i=0;i<32;i++)  {
		out[31-i]= in&01;
		in>>= 1;
		}
	return;
}


void frbits(byte in[], int* out)

{
	int i;

	for(i=0;i<32;i++) {
		*out<<=1;
		*out|= in[i];
		}

	return;
}


/* ----------------------------------------------------------------------- */


/*
 *	DES Algorithm
 */

char dbits[64];
char kbits[64];
struct {
	char tbits[56];
	} kround[16];



void sub(byte m1[], byte m2[], int box)

{
	int i,j,k;

	k= (m1[0]<<1)|m1[5];
	for(i=1;i<5;i++)
		k= (k<<1)|m1[i];

	j= s[64*box+k];
	for(i=3;i>=0;i--) {
		m2[i]= j&01;
		j>>= 1;
		}
	return;
}


void f(int ks,byte res[], byte inb[])

{
	int i;
	char spare[48];

	for(i=0;i<32;i++)
		spare[i]= inb[i];
	permute(spare,eb,48,32);
	for(i=0;i<48;i++)  { 
		spare[i]+= kround[ks-1].tbits[i];
		spare[i]&= 01;
		}

	for(i=0;i<8;i++)
		sub(&spare[6*i],&res[4*i],i);

	permute(res,P,32,32);

	return;
}


/* ------------------------------------------------------------------- */

void compkeys(int key[2])

// compute key schedule

{
	int i, j, k, t;
	char tkey[64];

	tobits(key[0],&tkey[0]);
	tobits(key[1],&tkey[32]);
	permute(tkey,pc1,56,64);

	for(i=0;i<16;i++) {
		for(t=0;t<krot[i];t++)
			for(j=0;j<27;j++) {
				k= tkey[j];
				tkey[j]= tkey[j+1];
				tkey[j+1]= k;
				k= tkey[j+28];
				tkey[j+28]= tkey[j+29];
				tkey[j+29]= k;
				}
		for(j=0;j<56;j++)
			kround[i].tbits[j]= tkey[j];
		permute(&kround[i].tbits[0],pc2,48,56);
		}
	return;
	}


int dotint(int i, int j)

{
	int k,m;

	m= 0;
	for(k=0;k<6;k++) {
		m+= (i&j&1);
		j>>=1;
		i>>=1;
		}
	return(m);
	}


// mkcycle

/* ------------------------------------------------------------------------ */


des(int input[], int output[], int fReverse) 

//	the des algorithm, decrypt if fReverse is true

{
	int i, j, k;
	int n;
	char fout[32];				/* crypto function output */

	//	to internal
	tobits(input[0],&dbits[0]);
	tobits(input[1],&dbits[32]);

	// initial permutation
	permute(dbits,ip,64,64);

	// Do rounds, note last round is exceptional
	for(i=1;i<=16;i++) {
		if(fReverse==0)
			f(i,fout,&dbits[32]);
		else
			f(17-i,fout,&dbits[32]);
		if(i!=16)
			for(j=0;j<32;j++) {
				k=dbits[j];
				dbits[j]= dbits[32+j];
				dbits[32+j]= (k+fout[j])&01;
				}
		else
			for(j=0;j<32;j++)
				dbits[j]= (dbits[j]+fout[j])&01;
		}

	 // final permutation
	permute(dbits,ipi,64,64);

	// pack back into 2 words
	frbits(&dbits[0],&output[0]);
	frbits(&dbits[32],&output[1]);

	return;
	}


/* ----------------------------------------------------------------------- */

