char msg[]= {
	'o','s','u','z','k','m','t','k','l','z',
	'y','f','y','v','t','m','d','h','k','t',
	'q','w','w','i','b','d','m','z','i','a',
	'n','z','n','t','w','d','b','v','b','h',
	'w','g','p','d','d','h','b','p','z','c',
	'r','j','m','d','s','w','n','z','t','h',
	'f','p','b','o','v','m','v','e','r','u',
	'a','t','t','h','c','i','y','l','n','t',
	'y','x','s','d','o','y','z','k','x','u',
	'y','p','s','w','b','u','h','z','x','j',
	'k','r','y','v','y','h','a','n','n','g',
	'q','z','v','l','m','c','r','h','i','j',
	'v','b','z','o','i','h','b','v','c','e',
	'f','p','m','c','c','o','p','i','s','g',
	'x','m','b','l','c','z','m','c','t','o',
	'x','t','w','d','g','y','e','c','v','u',
	'u','i','y','i','q','q','f','y','h','w',
	'm','d','z','p','k','a','u','u','r','t',
	'k','s','n','z','o','c','s','s','d','z',
	'j','b','p','m','n','d','b','p','p','w',
	's','c','f','f','b','l','a','d','x','k',
	'd','p','h','o','a','d','e','e','b','a',
	'g','k','n','b','g','l','e','l','n','d',
	'j','b','a','z','m','o','j','u','d','o'};

char w[]= {
	'f','n','w','a','d','l','z','j','k','m',
	'q','s','c','x','h','v','p','t','g','i',
	'b','o','e','y','r','u','e','t','x','q',
	'p','v','j','c','b','n','r','a','d','s',
	'k','h','i','y','o','g','u','l','m','z',
	'f','w','l','e','v','o','x','y','g','c',
	'd','o','z','w','t','p','j','r','h','i',
	'b','k','a','m','s','u','n','f','x','y',
	'c','v','q','w','e','i','t','h','n','p',
	'l','k','s','a','o','g','r','j','b','u',
	'z','d','f','m','o','d','t','z','c','r',
	'f','h','e','n','b','y','u','m','o','x',
	'a','w','v','g','l','j','s','i','k','p',
	'v','k','u','n','y','e','w','f','m','i',
	'c','o','j','l','h','g','a','p','t','z',
	'r','x','s','v','q','d','j','m','p','h',
	'v','o','x','r','i','f','k','b','e','c',
	'u','q','d','z','t','a','l','g','n','s',
	'w','y','r','g','j','y','z','b','n','q',
	'h','c','f','a','m','t','i','l','o','w',
	'v','e','p','u','x','s','k','d','z','q',
	'j','k','o','i','b','r','m','f','h','v',
	't','n','w','x','e','g','s','c','u','p',
	'y','a','d','l','u','a','x','t','o','r',
	'v','w','k','h','p','z','n','l','i','m',
	'v','q','c','j','f','g','e','y','s','d',
	'm','g','h','x','l','e','t','y','f','k',
	'z','s','r','a','b','n','o','u','p','c',
	'q','w','d','i','j','v','p','g','n','b',
	'r','t','f','v','o','w','s','c','z','x',
	'd','l','m','i','k','u','j','a','h','y',
	'e','q','z','e','d','i','p','g','u','o',
	's','m','f','b','r','x','j','c','y','w',
	'n','v','q','k','t','a','l','h','f','d',
	'p','s','m','l','y','k','x','z','w','j',
	'o','n','c','b','u','v','e','i','r','t',
	'h','a','q','g','m','i','g','h','u','o',
	's','l','y','c','d','j','v','q','x','b',
	't','r','e','f','k','w','n','p','a','z',
	'g','p','z','l','t','a','b','u','n','e',
	'j','s','f','v','k','r','w','m','i','h',
	'c','x','d','q','y','o','x','i','d','l',
	'e','t','v','z','y','h','u','b','q','n',
	'w','a','g','m','s','k','c','r','o','j',
	'p','f','w','h','m','f','s','g','u','z',
	'e','y','x','r','v','i','c','o','l','q',
	'k','p','b','d','a','n','j','t','i','k',
	'l','m','a','t','h','n','c','z','x','w',
	'u','o','g','s','v','y','b','q','f','p',
	'j','d','e','r','j','v','o','h','k','y',
	'z','c','l','u','x','e','s','f','w','t',
	'r','p','q','d','b','m','a','g','n','i'};
	
char tc[26], cmc[20],nw[26];

main(argn,argv)

int argn;
char *argv[];

{
	int i,j,k;
	int ntc,mc,wc,mo,co;
	int thresh;
	char a,*p,*q;

	p= argv[1];
	thresh= 1;
	if(argn>2)
		thresh= atoi(argv[2]);
	printf("letters compared: %s, threshhold: %d\n",p,thresh);
		
	ntc= 0;
	while((*p)!='\0')
		tc[ntc++]= *(p++);

	/*
	 *	mc - message column
	 *	wc - wheel column
	 *	mo - message offset
	 *	co - charaacter offset
	 */
	printf("message col, wheel, offset, char, matches\n");
	for(mc=0;mc<20;mc++) {
	  for(j=0;j<12;j++)
		cmc[j]= msg[j*20+mc];
	  for(wc=0;wc<20;wc++) {
	    for(i=0;i<26;i++)
		nw[i]= w[wc*26+i];
	    for(mo=18;mo==18;mo++) {
	      k= 0;
	      for(co=0;co<ntc;co++) {
		a= tc[co];
	    	p= &w[26*wc];
	    	for(j=0;j<26;j++)
			if(a==p[j])
				break;
	    	mvtrn(p,nw,j);
		i= match(cmc,nw,mo);
		k+= i;
		}
	      if(argn<=3)
	       if(k>thresh)
		printf("%d, %d, %d, %d\n",mc+1,wc+1,mo,k);
	      }
	    }
	  }

	printf("\ndone\n");
	exit();
}



mvtrn(p,q,i)

char p[],q[];
int i;


{
	int j;

	for(j=0;j<26;j++)
		q[j]= p[(i+j)%26];

	return;
}


match(a,b,n)

char a[], b[];
int n;

{
	int nm,r,i,k;
	k= n;
	nm= 0;
	for(i=0;i<12;i++) {
		n++;
		r= n- (20*(n/20));
		if(r==0)
			r= 1;
		if(a[i]==b[r])
			nm++;
		}

	return(nm);
}


pr(a,n,s)

char a[],*s;
int n;

{
	int i;

	printf("%s : ",s);
	for(i=0;i<n;i++)
		printf("%c ",a[i]);
	printf("\n");
	return;
}

