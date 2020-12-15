main(argn,argv)

int argn;
char *argv[];

{
	int i,j,n;
	int c1[2],c2[2];
	char b1[64], b2[64];
	short int coins[64];

	if((i=open(argv[1],0))<0) {
		printf("\ncannot open %s, quitting\n",argv[1]);
		exit();
		}

	lseek(i,8,0);
	for(;;)  {
		if(read(i,c1,8)<8)
			break;
		if(read(i,c2,8)<8)
			break;
		tobits(c1[0],b1);
		tobits(c1[1],&b1[32]);
		tobits(c2[0],&b2[0]);
		tobits(c2[1],&b2[32]);
		n= 0;
		for(j=0;j<64;j++)
			if(b1[j]==b2[j])
				coins[n++]=j+1;
		printf("\n\n%8x %8x vs %8x %8x, %d coincidences at\n",c1[0],c1[1],c2[0],c2[1],n);
		for(j=0;j<n;j++)
			printf(" %d",coins[j]);

		}
	printf("\n\nDone\n");
	exit();

}



tobits(in,out)

int in;
char out[];

/*
 *	to internal format
 */

{
	int i;

	for(i=0;i<32;i++)  {
		out[31-i]= in&01;
		in>>= 1;
		}
	return;
}
