//
//		Random Numbers
//


//  -----------------------------------------------------------------------------------------------------------


class X917
{
public:
	unsigned	m_rguState[4];
	unsigned	m_rguSeed[4];
	unsigned	m_rguKey[4];
	unsigned	m_rguI[4];
	X917();
	~X917();
	void X917::InitX917(int j, unsigned* puSeed);
	void X917::NextState()
{
}


class FIPS186
{
public:
	unsigned	m_rguState[16];
	unsigned	m_rguSeed[16];
	unsigned	m_rguK[16];
	enum {T1= 0x67452301, T2= 0xefcdab89, T3= 0x98badcfe, T4= 0x10325476, T5= 0xc3d2e1f0};
	FIPS186();
	~FIPS186();
	bool	G(unsigned* put, unsigned* puS);
	void	NextState();	
	void	Init(int j, unsigned* puSeed);
}


//  -----------------------------------------------------------------------------------------------------------


