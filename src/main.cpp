#include "socksserver.h"
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>

int main()
{
    SocksServer ss;

    return ss.listenning();
}
