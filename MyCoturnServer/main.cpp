#include <cstdio>
#include "socketListener.h"
int main()
{
	socketListener manager;
	manager.StartSocketListen();
    printf("hello from MyCoturnServer!\n");
    return 0;
}