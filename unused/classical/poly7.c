
// poly7
//	print polynomials as coefficients in a matrix table


// -------------------------------------------------------------------



prc1(mat)

char mat[];

{
	int i,m;

	m=0;
	printf("\t");
	for(i=0;i<64;i++)
	  if(mat[i]!=0) {
		if(m++>7) {
			printf("\n\t");
			m= 0;
			}
		printf("+ ");
		bin(i);
		printf(" ");
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
	printf("\n\nRepresentation as polynomial of %s\n",argv[1]);
	k= 0;
	for(;;) {
	  if(read(of,t,64)<=0)
		break;
	  for(i=0;i<64;i++) {
	    sum= 0;
	    for(j=0;j<64;j++)
		if(subset(j,i)==1)
			sum+= t[j];
	    coef[i]= sum%2;
	    }
	  printf("\n\nS(%d,%d):",k/4+1,k%4+1);
	  prc1(coef);
	  k++;
	  }
	printf("\ndone\n");
	exit();
}



// -------------------------------------------------------------------

