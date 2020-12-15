
// symlib.h

// ----------------------------------------------------------------------- 

// Ops

const short cNone= 0;
const short cPlus= 1;
const short cTimes= 2;
const short cVariable= 3;


class Node {
public: 
	short op;
	void* pLeft;
	void* pRight;
	Node() { op= cNone; pLeft= NULL; pRight=NULL; };
	bool Add(Node* pNode);
	bool Multiply(Node* pNode);
	bool Simplify();
	Node* Substitute(void* Var, Node* pExpression);
	void Print();
	Node* CopyNodes();
	};


bool Permute(short iIn, short iOut, short Perm[], void* pIn[], void* pOut[]);



// ----------------------------------------------------------------------- 
