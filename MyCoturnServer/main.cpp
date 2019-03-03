#include <cstdio>
#include "socketListener.h"
using namespace std;
int main()
{
	socketListener manager;
	manager.StartSocketListen();

	int i = 0;
	cin >> i;
    return 0;
}