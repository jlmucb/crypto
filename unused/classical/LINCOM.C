// lincom.c
//		linear combinations


/* ------------------------------------------------------------------ */


main(argn,argv)

int argn;
char *argv[];

{
	int i,j,k,n;
	int in, of;
	char t[64*4];
	char ht[64];
	short int cc[100];

	printf("\n\n16 fold linear combination maker\n",argv[1]);
	if(argn<2) {
		printf("lincom input-file offset/64 output-file\n");
		exit();
		}

	if((in=open(argv[1],0))<0) {
		printf("\nCannot open %s, quitting\n",argv[1]);
		exit();
		}
	i= atoi(argv[2]);
	lseek(in,64*4*i,0);
	if(read(in,t,64*4)<=0) {
		printf("cant get function values\n");
		exit();
		}
	close(in);
	prmat(t,"Function 1");
	prmat(&t[64],"Function 2");
	prmat(&t[128],"Function 3");
	prmat(&t[192],"Function 4");

	if((of=creat(argv[3],0666))<=0) {
		printf("Cant create %s\n",argv[3]);
		exit();
		}
	
	for(i=1;i<16;i++) {
		for(j=0;j<64;j++)
			ht[j]= 0;
		for(k=0;k<4;k++) {
			if((i&(1<<k))!=0) {
				for(j=0;j<64;j++)
					ht[j]^= t[64*k+j];
				}
			}
		write(of,ht,64);
		prmat(ht,"");
		}

	close(of);
	printf("\ndone\n");
	exit();
}


/* ------------------------------------------------------------------ */

