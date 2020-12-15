#define PRINT
int inf;
int round;
char inpcons[64],outcons[64],keycons[64];


/* ----------------------------------------------------------------------- */


main(argn,argv)

int argn;
char *argv[];

/*
 *	verify constriants
 *	Format of input/output files
 *		n size1 size2 ... sizen
 *		key1(64bits) size1*64bits of data
 *		...
 *		keyn(64) sizen*64bits of data
 */

{
	int i, j,nz,no,n;
	int key[2], inblk[2], outblk[2];
	int ico[2],oco[2],kco[2];
	extern kbits[64];
	extern tobits();

	round= atoi(argv[2]);
	printf("constraint test bed, round %d, ",round);
	printf(" Input: %s\n",argv[1]);
	nz= 0;
	no= 0;

	if((inf=open(argv[1],0))<0) {
		printf("\nCannot open %s quittting\n",argv[2]);
		exit();
		}

	read(inf,key,8);
	printf("key: %08x %08x\n",key[0],key[1]);
	compkeys(key);
	read(inf,ico,8);
	printf("input constraint: %08x %08x\n",ico[0],ico[1]);
	tobits(ico[0],&inpcons[0]);
	tobits(ico[1],&inpcons[32]);
	read(inf,oco,8);
	printf("output constraint: %08x %08x\n",oco[0],oco[1]);
	tobits(oco[0],&outcons[0]);
	tobits(oco[1],&outcons[32]);
	read(inf,kco,8);
	printf("key constraint: %08x %08x\n",kco[0],kco[1]);
	tobits(kco[0],&keycons[0]);
	tobits(kco[1],&keycons[32]);
	prbit("Key    ",kbits,64);printf("\n");
	prbit("Incnst ",inpcons,64);printf("\n");
	prbit("Outcnst",outcons,64);printf("\n");
	prbit("Keycnst",keycons,64);printf("\n");
	n= 0;
	while(1) {
		if(read(inf,inblk,8)<=0)
			break;
		printf("\tinput: %08x %08x, ",inblk[0],inblk[1]);
		i= around(inblk,outblk,round,inpcons,outcons,keycons);
		printf(" output: %08x %08x\n",outblk[0],outblk[1]);
		n++;
		if(i==0)
			nz++;
		if(i==1)
			no++;
		}
	printf("Number of 1's: %d, number of 0's: %d, Total: %d\n",no,nz,n);
	close(inf);
	printf("\nDone\n");
	exit();
}


/* ----------------------------------------------------------------------- */


