
// ht64.c
//		headamard transform

/* -------------------------------------------------------------------- */


main(int argn, char* argv[])

{
	int i,j,k,n;
	int high, low;
	int of, sum;
	char t[64];
	char ht[64];
	short int cc[100];

	if((of=open(argv[1],0))<0) {
		printf("\nCannot open %s, quitting\n",argv[1]);
		exit();
		}
	printf("\n\nHadamard transform of %s\n",argv[1]);
	n= 0;
	for(;;) {
	  if(read(of,t,64)<=0)
		break;
	  for(i=0;i<64;i++) {
	    sum= 0;
	    for(j=0;j<64;j++) {
			k= (dotint(i,j)+t[j])%2;
			sum+= (1-2*k);
			}
	    ht[i]= sum;
	    }

	  printf("\n\nS(%d,%d):",n/4+1,n%4+1);
	  n++;
	  prmat(ht);
	  high= 0;
	  low= 0;
	  for(i=0;i<64;i++) {
		if(ht[i]>high)
			high= ht[i];
		if(ht[i]<low)
			low= ht[i];
		}
	  for(i=0;i<=(high-low);i++)
		cc[i]= 0;
	  for(i=0;i<64;i++)
		cc[ht[i]-low]++;
	  for(i=0;i<=(high-low);i++)
	    if(cc[i]>0)
		printf(" [%d,%d] ",cc[i],i+low);
	  }

	printf("\ndone\n");
	exit();
}


/* -------------------------------------------------------------------- */

