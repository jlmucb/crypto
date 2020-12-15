char q[64*64];

main(argn,argv)

int argn;
char *argv[];

{
	int i,j,k;
	int high, low;
	int of, sum;
	char t[64], ft[64];
	short int cc[100];

	if((of=open(argv[1],0))<0) {
		printf("\nCannot open %s, quitting\n",argv[1]);
		exit();
		}
	genq();
	for(;;) {
	  if(read(of,t,64)<=0)
		break;
	  for(i=0;i<64;i++) {
	    sum= 0;
	    for(j=0;j<64;j++)
		sum+= t[j]*(1-2*q[64*j+i]);
	    ft[i]= sum;
	    }
/*
	  high= 0;
	  low= 0;
	  for(i=0;i<64;i++) {
		if(ft[i]>high)
			high= ft[i];
		if(ft[i]<low)
			low= ft[i];
		}
*/
	high= 32;
	low= -12;
	  for(i=0;i<=(high-low);i++)
		cc[i]= 0;
	  for(i=0;i<64;i++)
		cc[ft[i]-low]++;
	  printf("\n");
	  for(i=0;i<=(high-low);i=i+2)
		printf("%3d",cc[i]);
	  printf(" -- [%d,%d]",low,high);
	  }

	printf("\ndone\n");
	exit();
}

genq()
{
	int i,j,k,m,l;

	for(i=0;i<63;i++)
	  for(j=0;j<63;j++)  {
		l= i&j;
		m= 0;
		for(k=0;k<6;k++)  { 
		    m+= l&1;
		    l>>= 1;
		    }
		m%= 2;
		q[64*i+j]= m;
		}

#ifdef DEBUG
	printf("\nqmat\n");
	for(i=0;i<64;i++) {
		for(j=0;j<64;j++)
		   printf("%d",m=q[64*i+j]);
		printf("\n");
		}
#endif
	return;
}


prmat(mat)

char mat[];

{
	int i,j,k;

	for(i=0;i<4;i++) {
	  printf("\t");
	  for(j=0;j<16;j++)
		printf("%3d ",k=mat[16*i+j]);
	  printf("\n");
	  }

	return;
}
