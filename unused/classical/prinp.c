int inf, ouf;
int radix;
char *cp;
int left;
char buf[4096];


// prinp.c
//		transform from numbers to binary

main(int argn, char *argv[])

{
	int i, j, k;
	char *p, *q;
	char a,b;

	printf("\nPrepare input\n");
	printf("\tInput: %s\n\tOutput: %s\n", argv[2], argv[1]);
	left= 0;

	if((inf=open(argv[2],0))<0) {
		printf("\nCannot open %s quittting\n",argv[2]);
		exit();
		}
	if((ouf=creat(argv[1],0666))<0)  {
		printf("\nCannot creat %s quitting\n",argv[1]);
		exit();
		}
	read(inf,&a,1);
	switch(a) {
	  case 'b':
		radix= 2;
		break;
	  case 'o':
		radix= 8;
		break;
	  case 'h':
		radix= 16;
		break;
	  default:
		printf("\nUnknown radix, quitting\n");
		exit();
	  }
	printf("Radix: %d\n",radix);

	for(;;) {
		if((i=get())<=0)
			break;
		if(((i<'0')||(i>'9'))&&((i<'a')||(i>'f')))
			continue;
		switch(radix) {
		  case 2:
			k= get2(i);
			break;
		  case 8:
			k= get8(i);
		  	break;
		  case 16:
			k= get16(i);
			break;
		  }
		write(ouf,&k,4);
		}

	close(inf);
	close(ouf);
	printf("nDone\n");
	exit();
}


/* ---------------------------------------------------------------------- */


get()

{
	int i,j;

	if(left<=0) {
		left= read(inf,cp=buf,4096);
		if(left<=0)
			return(-1);
		}
	left--;
	return(*(cp++));
}


get2(int n)

{
	int i,j,k;

	if((n=='0')||(n=='1'))
		k= n-'0';
	else
		return(0);
	for(i=0;i<31;i++) {
		j= get();
		if((j!='0')&&(j!='1'))
			break;
		k<<= 1;
		k|= (j-'0');
		}

	return(k);
}


get8(int n)

{
	int i,j,k;

	if((n>='0')&&(n<='7'))
		k= n-'0';
	else
		return(0);
	for(i=0;i<10;i++) {
		j= get();
		if((j<'0')||(j>'7'))
			break;
		k<<= 3;
		k|= (j-'0');
		}

	return(k);
}


get16(int n)

{
	int i,j,k;

	if((n>='0')&&(n<='9'))
		k= n-'0';
	else if((n>='a')&&(n<='f'))
		k= n-'a'+10;
	else
		return(0);
	for(i=0;i<7;i++) {
		j= get();
		if(((j<'0')||(j>'9'))&&((j<'a')||(j>'f')))
			break;
		k<<= 4;
		if(j>'9')
			k|= j-'a'+10;
		else
			k|= j-'0';
		}

	return(k);
}


/* ---------------------------------------------------------------------- */
