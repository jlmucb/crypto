struct {
	int co[64];
	}  eq[32];


main(argn,argv)

int argn;
char *argv[];

{
	int i,j,k;
	int of, sum;
	char t[64];
	char coef[64];

	if((of=open(argv[1],0))<0) {
		printf("\nCannot open %s, quitting\n",argv[1]);
		exit();
		}
	printf("\n\nPolynomial table: %s\n",argv[1]);
	for(i=0;i<32;i++)
		for(j=0;j<64;j++)
			eq[i].co[j]= 0;
	k= 0;
	for(;;) {
	  if(read(of,t,64)<=0)
		break;
	  for(i=0;i<64;i++) {
	    sum= 0;
	    for(j=0;j<64;j++)
		if(subset(j,i)==1)
			sum+= t[j];
	    eq[k].co[i]= sum%2;
	    }
	  k++;
	  }
	close(of);
	prtab();
	printf("\ndone\n");
	exit();
}


prtab()


{
	int i,j,k,m;

	printf("\n\n\n\n\n");
	for(i=0;i<32;i++) {
		printf("\n%2d ",i+1);
		for(k=0;k<6;k++)
		  for(j=0;j<64;j++)
		    if(pc(j)==k)
			printf(" %d", (m=eq[i].co[j]));
		}

	printf("\n\n");
	for(k=0;k<6;k++)
	  for(j=0;j<64;j++)
		if(pc(j)==k) {
			printf("\n");
			bin(j);
			printf("  ");
			}

	printf("\n\n\n\n\n");
	for(i=0;i<32;i++) {
		printf("%2d ",i+1);
		for(j=0;j<64;j++)
			printf("%d",eq[i].co[j]);
		printf("\n");
		}
	return;
}


bin(i)

int i;

{
	int j;

	if(i==0) {
		printf("C");
		return;
		}
	for(j=0;j<6;j++) {
		if((i&040)!=0)
			printf("%d",j+1);
		i<<= 1;
		}

	return;
}





subset(a,b)

int a,b;

{
	int i;

	for(i=0;i<6;i++) {
		if((a&1)==1)
			if((b&1)==0)
				return(0);
		a>>= 1;
		b>>= 1;
		}
	return(1);
}

pc(i)

{
	int j,k;

	k= 0;
	for(j=0;j<6;j++) {
		if((i&1)!=0)
			k++;
		i>>=1;
		}
	return(k);
}
