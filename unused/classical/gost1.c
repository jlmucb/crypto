
//  GOST 

typedef unsigned long u4;

typedef unsigned char byte;



typedef struct {
	u4 k[8];

	/* Constant s boxes, set up in gost_init(). */
	char k87[256],k65[256],k43[256],k21[256];
} gost_ctx;


/* 
 *	Note: encrypt and decrypt expect full blocks padding blocks is 
 *	caller’s responsibility. All bulk encryption is done in ECB mode 
 *	by these calls. 
 *
 *	Forward References
 */
void gost_enc(gost_ctx *, u4 *, int);
void gost_dec(gost_ctx *, u4 *, int);
void gost_key(gost_ctx *, u4 *);
void gost_init(gost_ctx *);
void gost_destroy(gost_ctx *);

#ifdef __alpha /* Any other 64 bit machines? */
typedef unsigned int word32;
#else
typedef unsigned long word32;
#endif



kboxinit(gost_ctx *c)

{

	int i;


	byte k8[16] = {14, 4, 13, 1, 2, 15, 11, 8, 3, 
		       10, 6, 12, 5, 9, 0, 7};
	byte k7[16] = {15, 1, 8, 14, 6, 11, 3, 4, 9, 
		        7, 2, 13, 12, 0, 5, 10 };
	byte k6[16] = {10, 0, 9, 14, 6, 3, 15, 5, 1,
		       13, 12, 7, 11, 4, 2, 8 };
	byte k5[16] = { 7, 13, 14, 3, 0, 6, 9, 10, 1,
		        2, 8, 5, 11, 12, 4, 15 };
	byte k4[16] = { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3,
			15, 13, 0, 14, 9 };
	byte k3[16] = {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3,
			4, 14, 7, 5, 11 };
	byte k2[16] = { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9,
			7, 5, 10, 6, 1 };
	byte k1[16] = {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3,
			14, 5, 0, 12, 7 };

	for (i = 0; i < 256; i++) {
		c->k87[i] = k8[i >> 4] << 4 | k7[i & 15];
		c->k65[i] = k6[i >> 4] << 4 | k5[i & 15];
		c->k43[i] = k4[i >> 4] << 4 | k3[i & 15];
		c->k21[i] = k2[i >> 4] << 4 | k1[i & 15];
	}
}



static word32 f(gost_ctx *c,word32 x)
{
	x = c->k87[x>>24 & 255] << 24 | c->k65[x>>16 & 255] << 16 |
	c->k43[x>> 8 & 255] << 8 | c->k21[x & 255];
	/* Rotate left 11 bits */
	return x<<11 | x>>(32-11);
}



void gostcrypt(gost_ctx *c, word32 *d)
{
	register word32 n1, n2; /* As named in the GOST */

	n1 = d[0];
	n2 = d[1];

	/* Instead of swapping halves, swap names each round */
	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);
	
	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);
	
	d[0] = n2; d[1] = n1;
}



void gostdecrypt(gost_ctx *c, u4 *d)

{
	register word32 n1, n2; /* As named in the GOST */

	n1 = d[0]; n2 = d[1];

	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

	d[0] = n2; d[1] = n1;
}


void gost_enc(gost_ctx *c, u4 *d, int blocks)
{
int i;


for(i=0;i
 
gostcrypt(c,d);
d+=2;

}

}



void gost_dec(gost_ctx *c, u4 *d, int blocks){

int i;



for(i=0;i 
gostdecrypt(c,d);

d+=2;

}

}



void gost_key(gost_ctx *c, u4 *k){

int i;

for(i=0;i<8;i++) c–>k[i]=k[i];

}



void gost_init(gost_ctx *c){

kboxinit(c);

}



void gost_destroy(gost_ctx *c){

int i;

for(i=0;i<8;i++) c–>k[i]=0;

}



void main(void){

gost_ctx gc;

u4 k[8],data[10];

int i;



/* Initialize GOST context. */

gost_init(&gc);



/* Prepare key––a simple key should be OK, with this many rounds! */

for(i=0;i<8;i++) k[i] = i;

gost_key(&gc,k);



/* Try some test vectors. */

data[0] = 0; data[1] = 0;

gostcrypt(&gc,data);

printf(“Enc of zero vector: %08lx %08lx\n”,data[0],data[1]);

gostcrypt(&gc,data);

printf(“Enc of above: %08lx %08lx\n”,data[0],data[1]);

data[0] = 0xffffffff; data[1] = 0xffffffff;

gostcrypt(&gc,data);

printf(“Enc of ones vector: %08lx %08lx\n”,data[0],data[1]);

gostcrypt(&gc,data);

printf(“Enc of above: %08lx %08lx\n”,data[0],data[1]);



/* Does gost_dec() properly reverse gost_enc()? Do

we deal OK with single–block lengths passed in gost_dec()?

Do we deal OK with different lengths passed in? */



/* Init data */

for(i=0;i<10;i++) data[i]=i;

/* Encrypt data as 5 blocks. */



gost_enc(&gc,data,5);

/* Display encrypted data. */



for(i=0;i<10;i+=2) printf(“Block %02d = %08lx %08lx\n”,

i/2,data[i],data[i+1]);



/* Decrypt in different sized chunks. */

gost_dec(&gc,data,1);

gost_dec(&gc,data+2,4);

printf(“\n”);



/* Display decrypted data. */

for(i=0;i<10;i+=2) printf(“Block %02d = %08lx %08lx\n”,

i/2,data[i],data[i+1]);



gost_destroy(&gc);

}



