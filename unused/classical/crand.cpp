//
//		Random Numbers
//
#include "crand.h"


//  -----------------------------------------------------------------------------------------------------------


void X917::X917()
{
	memset((void*)m_rguState,0,16);
	memset((void*)m_rguSeed,0,16);
	memset((void*)m_rguKey,0,16);
	memset((void*)m_rguI,0,16);
}


void X917::~X917()
{
	memset((void*)m_rguState,0,16);
	memset((void*)m_rguSeed,0,16);
}


void X917::Init(int j, unsigned* puSeed)
{
	int k= (j>16)?j:16;

	memcpy((void*)m_rguSeed, (void*)puSeed, k);
	if(k<16)
	{
		memset((void*)m_rguSeed+k,0,16-k);
	}

	//
	// I= E(k,D), D is date
	//
}


void X917::NextState()
{
	//
	// State= E(k,I^Seed), Seed= E(k,State^I)
	//
}


//  -----------------------------------------------------------------------------------------------------------


void FIPS186::FIPS186()
{
	memset((void*)m_rguState,0,16);
	memset((void*)m_rguSeed,0,16);
	memset((void*)m_rguK,0,16);
}


void FIPS186::~FIPS186()
{
	memset((void*)m_rguState,0,16);
	memset((void*)m_rguSeed,0,16);
}


bool	FIPS186::G(unsigned* put, unsigned* puS)
{

	// pad c with 0s for 512 bit blocks
	// apply SHA state change to get new H's
	return(true);
}


void FIPS186::Init(int j, unsigned* puSeed)
{
	int k= (j>16)?j:16;

	memcpy((void*)m_rguSeed, (void*)puSeed, k);
	if(k<16)
	{
		memset((void*)m_rguSeed+k,0,16-k);
	}
	//
	// I= E(k,D),
	//
}


void FIPS186::NextState()
{
	// State= G(t, Seed), Seed= (1+Seed+State) (mod 2**b), output State
}

//  -----------------------------------------------------------------------------------------------------------


