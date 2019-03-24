#include "socksserver.h"
#include "tools.hpp"
#include <string.h>
#include <iostream>
#include <stdio.h>

#define UNUSED(x) (void)x;

#if defined(_WIN32)
#include <windows.h>
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>

/**
    The below definitions are references from https://github.com/mkulke/ftplibpp,
    please contact me in advance for any questions,
    thanks
*/
#if defined(_WIN32)
#define SETSOCKOPTOPTVALTYPE (const char *)
#else
#define SETSOCKOPTOPTVALTYPE (void *)
#endif

#if defined(_WIN32)
#define SockRead(x,y,z) recv(x,(char*)y,z,0)
#define SockWrite(x,y,z) send(x,(char*)y,z,0)
#define SockClose closesocket
#else
#define SockRead read
#define SockWrite write
#define SockClose close
#endif

#if defined(_WIN32)
typedef int socklen_t;
#endif

#if defined(_WIN32)
#define memccpy _memccpy
#define strdup _strdup
#endif

SocksServer::SocksServer()
{
    tv.tv_sec = 20;
    tv.tv_usec = 0;
}

int SocksServer::listenning(uint16_t iPort, const char *iAddr)
{
    lstPort = htons(iPort);

#ifdef _WIN32
    if ((lstAddr = inet_addr(iAddr)) == -1)
#else
    if (0 == inet_aton(iAddr, (in_addr*)&lstAddr)) {
#endif
        std::cerr << "Invalid address: " << iAddr << "\n";
        std::cerr.flush();
        return -1;
    }

    sockaddr_in sSIn;
    memset(&sSIn, 0, sizeof(sSIn));
    sSIn.sin_family = AF_INET;
    sSIn.sin_port = lstPort;
    memccpy(&sSIn.sin_addr, &lstAddr, 1, sizeof(lstAddr));

    int sControl = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sControl == -1) {
        perror("socket");
        return -1;
    }

    int on = 1;
    if (setsockopt(sControl, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPTOPTVALTYPE &on, sizeof(on)) == -1) {
        perror("setsockopt SO_REUSEADDR");
        SockClose(sControl);
        return -1;
    }

    if ( 0 != bind(sControl, (sockaddr*)&sSIn, sizeof(sSIn))) {
        perror("bind");
        SockClose(sControl);
        return -1;
    }

    if (0 != listen(sControl, 1000)) {
        perror("listen");
        SockClose(sControl);
        return -1;
    }

    while (true) {
        sockaddr_in cSIn;
        socklen_t cSInLen = sizeof(cSIn);
        memset(&cSIn, 0, sizeof(cSIn));

        int nControl = accept(sControl, (sockaddr*)&cSIn, &cSInLen);
        if (nControl < 0) {
            perror("accept");
            return -1;
        }

        distributor(nControl, cSIn);
    }

    return 0;
}

void SocksServer::distributor(int iSControl, const sockaddr_in &iCSIn)
{
    //inspector buffer
    char buf[1]{0};
    int fd;
    int rcvsz;

    fd = MARKTOOLS::SocketWaitRead(tv, {iSControl});

    if (fd == 0) {
        goto end;
    }

    if (fd < 0) {
        perror("SocketWaitRead");
        goto end;
    }

    rcvsz = SockRead(iSControl, buf, sizeof(buf));
    if (rcvsz == 0) {
        goto end;
    }

    if (rcvsz == -1) {
        std::cerr << "SockRead" << std::endl;
        goto end;
    }

    if (0x04 == buf[0]) {
        serveV4(iSControl, iCSIn);
    } else if (0x05 == buf[0]) {
        greetingV5(iSControl, iCSIn);
    }

    if (false) {
end:
        SockClose(iSControl);
    }

    return;
}

void SocksServer::serveV4(int iSControl, const sockaddr_in &iCSIn)
{
    //read command from client
    char buf[1024] {0, };
    buf[0] = 0x04;
    S4CHeader* cHeader = (S4CHeader*)buf;
    size_t offset{1};
    //
    int fd;
    int rcvsz;
    S4SHeader sHeader;

    while (true) {
        fd = MARKTOOLS::SocketWaitRead(tv, {iSControl});

        if (fd == 0) {
            goto end;
        }

        if (fd < 0) {
            perror("SocketWaitRead");
            goto end;
        }

        rcvsz = SockRead(iSControl, buf + offset, sizeof(buf) - offset - 1);
        if (rcvsz == 0) {
            goto end;
        }

        if (rcvsz == -1) {
            std::cerr << "SockRead" << std::endl;
            goto end;
        }

        offset += rcvsz;

        if (offset > sizeof(buf) - 2) {
            std::cerr << "SockRead data size to long" << std::endl;

            goto end;
        }

        if (offset > 8 && buf[offset - 1] == 0x00) {
            break;
        }
    }

    //minimum client header size if 10 bytes(1 byte ID and terminated with a null 0x00)
    if (offset < 9) {
        goto end;
    }

    sHeader.dstPort = (uint16_t)random();
    sHeader.dstIp = (uint32_t)random();

    if (0x04 != cHeader->version || (0x01 != cHeader->cmdCode && 0x02 != cHeader->cmdCode)) {
        sHeader.status = 0x5B;
        SockWrite(iSControl, &sHeader, sizeof(S4SHeader));

        goto end;
    }

#ifdef _WIN32
    //todo, convert inet_ntoa to windows compatibility
#else
    addSession(std::string(inet_ntoa(iCSIn.sin_addr)) + ":" + std::to_string(iCSIn.sin_port) + ":" + "V4",
               std::map<std::string, Variant>{
                   {std::string("DSTPORT"), Variant(cHeader->portNum)},
                   {std::string("DSTIP"), Variant(cHeader->ipaddr)},
                   {std::string("USERID"), Variant(std::string(cHeader->userId))}
               });
#endif

    //request to connect
    if (0x01 == cHeader->cmdCode) {
        ConnectV4(iSControl, cHeader->portNum, cHeader->ipaddr);
    } else if (0x02 == cHeader->cmdCode) {
        BindV4(iSControl, cHeader->portNum, cHeader->ipaddr, std::string(cHeader->userId), iCSIn);
    }

end:
    SockClose(iSControl);
    removeSession(std::string(inet_ntoa(iCSIn.sin_addr)) + ":" + std::to_string(iCSIn.sin_port) + ":" + "V4");
}

void SocksServer::serveV5(int iSControl, const sockaddr_in &iCSIn)
{
    char buf[1024]{0, };
    S5CHeader* cHeader = (S5CHeader*)buf;
    size_t offset{0};
    int recvLen;
    int fd;

    while (true) {
        fd = MARKTOOLS::SocketWaitRead(tv, {iSControl});
        if (fd == 0) {
            goto end;
        }

        if (fd < 0) {
            perror("SocketWaitRead");
            goto end;
        }

        recvLen = SockRead(iSControl, buf + offset, sizeof(buf) - offset);
        if (-1 == recvLen) {
            goto end;
        }

        if (0 == recvLen) {
            goto end;
        }

        offset += recvLen;

        if (offset >=  sizeof(S5CHeader) && offset == cHeader->getTotalLength()) {
            break;
        }
    }

    if (0x01 == cHeader->addrType || 0x03 == cHeader->addrType || 0x04 == cHeader->addrType) {
        //connect
        if (0x01 == cHeader->cmd) {
#ifdef _WIN32
            //todo, convert inet_ntoa to windows compatibility
#else
            addSession(std::string(inet_ntoa(iCSIn.sin_addr)) + ":" + std::to_string(iCSIn.sin_port) + ":" + "V5",
                       std::map<std::string, Variant>{
                           {std::string("DSTPORT"), Variant(cHeader->getPort())},
                           {std::string("DSTIP"), Variant(cHeader->getIPV4Addr())}
                       });
#endif

            ConnectV5(iSControl, cHeader);
        }
    } else {
        //todo
    }

    //todo, serve socks5
end:
    SockClose(iSControl);
    removeSession(std::string(inet_ntoa(iCSIn.sin_addr)) + ":" + std::to_string(iCSIn.sin_port) + ":" + "V5");
}

void SocksServer::greetingV5(int iSControl, const sockaddr_in &iCSIn)
{
    char buf[1024]{0, };
    buf[0] = 0x05;
    size_t offset{1};
    int fd;
    int rcvsz;
    size_t idx;
    size_t idy;
    int authed = 0;

    while (true) {
        fd = MARKTOOLS::SocketWaitRead(tv, {iSControl});
        if (fd == 0) {
            goto end;
        }

        if (fd < 0) {
            perror("SocketWaitRead");
            goto end;
        }

        rcvsz = SockRead(iSControl, buf + offset, sizeof(buf) - offset);
        if (rcvsz == 0) {
            goto end;
        }

        if (rcvsz == -1) {
            std::cerr << "SockRead" << std::endl;
            goto end;
        }

        offset += rcvsz;
        if (offset > (size_t)buf[1] + 2) {
            std::cerr << "Error format of greeting message" << std::endl;
            goto end;
        }

        if (offset == (size_t)buf[1] + 2) break;

        continue;
    }

    for (idx = 2; idx < offset; idx++) {
        for (idy = 0; idy < sizeof(authMethodsLst); idy++) {
            if (buf[idx] != authMethodsLst[idy]) continue;

            authed = -1;
            if (buf[idx] == 0x00) {
                //auth the method of 0x00
                authed = 1;
                SockWrite(iSControl, "\x05\x00", 2);
                break;
            } else if (0x01 == buf[idx]) {
                //todo, auth the method of 0x01

                break;
            }
        }

        if (0 != authed) break;
    }

    if (-1 == authed) {
        goto end;
    }

    serveV5(iSControl, iCSIn);

    if (false) {
end:
        SockClose(iSControl);
    }

    return;
}

int SocksServer::connTo(uint16_t iPort, uint32_t iAddr)
{
    int trdControl;
    sockaddr_in trdIn;
    int on = 1;

    memset(&trdIn, 0, sizeof(sockaddr_in));

    trdIn.sin_family = AF_INET;
    trdIn.sin_port = iPort;
    memccpy(&trdIn.sin_addr, &iAddr, 1, sizeof(iAddr));

    trdControl = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (trdControl == -1) {
        perror("socket");
        goto end;
    }


    if (setsockopt(trdControl, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPTOPTVALTYPE &on, sizeof(on)) == -1) {
        perror("setsockopt SO_REUSEADDR");
        SockClose(trdControl);
        trdControl = -1;
        goto end;
    }

    if (0 != connect(trdControl, (sockaddr*)&trdIn, sizeof(sockaddr_in))) {
        perror("connect");
        SockClose(trdControl);
        trdControl = -1;
        goto end;
    }

end:
    return trdControl;
}

int SocksServer::connTo(uint16_t iPort, const IPV6Addr &iAddr)
{
    int trdControl;
    sockaddr_in6 trdIn;
    int on = 1;

    memset(&trdIn, 0, sizeof(sockaddr_in6));

    trdIn.sin6_family = AF_INET6;
    trdIn.sin6_port = iPort;
    memccpy(&trdIn.sin6_addr, &iAddr, 1, sizeof(iAddr));

    trdControl = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (trdControl == -1) {
        perror("socket");
        goto end;
    }


    if (setsockopt(trdControl, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPTOPTVALTYPE &on, sizeof(on)) == -1) {
        perror("setsockopt SO_REUSEADDR");
        SockClose(trdControl);
        trdControl = -1;
        goto end;
    }

    if (0 != connect(trdControl, (sockaddr*)&trdIn, sizeof(sockaddr_in6))) {
        perror("connect");
        SockClose(trdControl);
        trdControl = -1;
        goto end;
    }

end:
    return trdControl;
}

int SocksServer::bindOn(uint16_t iPort, uint32_t iAddr)
{
    int trdControl;
    sockaddr_in trdIn;
    int on = 1;

    memset(&trdIn, 0, sizeof(sockaddr_in));

    trdIn.sin_family = AF_INET;
    trdIn.sin_port = iPort;
    memccpy(&trdIn.sin_addr, &iAddr, 1, sizeof(iAddr));

    trdControl = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (trdControl == -1) {
        perror("socket");
        goto end;
    }


    if (setsockopt(trdControl, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPTOPTVALTYPE &on, sizeof(on)) == -1) {
        perror("setsockopt SO_REUSEADDR");
        SockClose(trdControl);
        trdControl = -1;
        goto end;
    }

    if (0 != bind(trdControl, (sockaddr*)&trdIn, sizeof(sockaddr_in))) {
        perror("bind");
        SockClose(trdControl);
        trdControl = -1;
        goto end;
    }

end:
    return trdControl;
}

int SocksServer::bindOn(uint16_t iPort, const IPV6Addr &iAddr)
{
    int trdControl;
    sockaddr_in6 trdIn;
    int on = 1;

    memset(&trdIn, 0, sizeof(sockaddr_in6));

    trdIn.sin6_family = AF_INET6;
    trdIn.sin6_port = iPort;
    memccpy(&trdIn.sin6_addr, &iAddr, 1, sizeof(iAddr));

    trdControl = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (trdControl == -1) {
        perror("socket");
        goto end;
    }

    if (setsockopt(trdControl, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPTOPTVALTYPE &on, sizeof(on)) == -1) {
        perror("setsockopt SO_REUSEADDR");
        SockClose(trdControl);
        trdControl = -1;
        goto end;
    }

    if (0 != bind(trdControl, (sockaddr*)&trdIn, sizeof(sockaddr_in6))) {
        perror("bind");
        SockClose(trdControl);
        trdControl = -1;
        goto end;
    }

end:
    return trdControl;
}

void SocksServer::ConnectV4(int iSControl, uint16_t iPort, uint32_t iAddr)
{
    S4SHeader sHeader;
    sHeader.dstPort = iPort;
    memccpy(&sHeader.dstIp, &iAddr, 1, sizeof(iAddr));
    int trdControl;
    int fd;
    int rcvsz;
    int wrtsz;
    char buf[1024]{0, };

    trdControl = connTo(iPort, iAddr);
    if (-1 == trdControl) {
        sHeader.status = 0x5C;
        SockWrite(iSControl, &sHeader, sizeof(S4SHeader));

        goto end;
    }

    sHeader.status = 0x5A;
    SockWrite(iSControl, &sHeader, sizeof(S4SHeader));

    while (true) {
        fd = MARKTOOLS::SocketWaitRead(tv, {iSControl, trdControl});

        if (0 == fd) {
            SockClose(trdControl);

            goto end;
        }

        if (-1 == fd) {
            perror("SocketWaitRead");
            SockClose(trdControl);

            goto end;
        }

        rcvsz = SockRead(fd, buf, sizeof(buf) - 1);
        if (rcvsz < 0) {
            perror("SockRead");
        }

        if (rcvsz == 0) {
            SockClose(trdControl);

            goto end;
        }

        wrtsz = SockWrite(fd == iSControl ? trdControl : iSControl, buf, rcvsz);
        if (wrtsz != rcvsz) {
            perror("SockWrite");
            SockClose(trdControl);

            goto end;
        }
    }

end:
    return;
}

void SocksServer::BindV4(int iSControl, uint16_t iPort, uint32_t iAddr, const std::string &iUsrId, const sockaddr_in &iCSIn)
{
    S4SHeader sHeader;
    sockaddr_in sIn;
    uint sInLen = sizeof(sockaddr);

    memset(&sIn, 0, sizeof(sIn));
    int trdControl;
    int _;
    int fd;
    char buf[1024]{0, };
    int rcvsz;
    int wrtsz;
    bool flag{false};

    auto sessionVal = getSession(std::string(inet_ntoa(iCSIn.sin_addr)) + ":" + std::to_string(iCSIn.sin_port) + ":" + "V4");

    if (sessionVal.empty() ||
            iPort != std::get<uint16_t>(sessionVal["DSTPORT"]) ||
            iAddr != std::get<uint32_t>(sessionVal["DSTIP"]) ||
            iUsrId != std::get<std::string>(sessionVal["USERID"]))
    {
        sHeader.status = 0x5C;
        SockWrite(iSControl, &sHeader, sizeof(S4SHeader));
        goto end;
    }

    //listenning a new port, then return self address (or 0.0.0.0) and the port to the client
    _ = bindOn();
    if (-1 == _) {
        sHeader.status = 0x5C;
        SockWrite(iSControl, &sHeader, sizeof(S4SHeader));
        goto end;
    }

    if (0 != getsockname(_, (sockaddr*)&sIn, &sInLen)) {
        SockClose(_);
        perror("getsockname");
        sHeader.status = 0x5C;
        SockWrite(iSControl, &sHeader, sizeof(S4SHeader));
        goto end;
    }

    if (0 != listen(_, 1000)) {
        SockClose(_);
        perror("listen");
        sHeader.status = 0x5C;
        SockWrite(iSControl, &sHeader, sizeof(S4SHeader));
        goto end;
    }

    sHeader.status = 0x5A;
    sHeader.dstPort = sIn.sin_port;
    SockWrite(iSControl, &sHeader, sizeof(S4SHeader));

    while (true) {
        trdControl = accept(_, (sockaddr*)&sIn, &sInLen);
        if (-1 == trdControl) {
            perror("accept");
            continue;
        }

        if (0 != memcmp(&sIn.sin_addr, &iAddr, sizeof(uint32_t))) {
            std::cout << "Incoming address is mismatched, disconnect it" << std::endl;
            sHeader.status = 0x5C;
            SockWrite(iSControl, &sHeader, sizeof(S4SHeader));
            SockClose(trdControl);
            continue;
        }

        sHeader.status = 0x5A;
        sHeader.dstPort = sIn.sin_port;
        memccpy(&sHeader.dstIp, &sIn.sin_addr, 1, sizeof(sIn.sin_addr));
        SockWrite(iSControl, &sHeader, sizeof(S4SHeader));

        while (true) {
            fd = MARKTOOLS::SocketWaitRead(tv, {iSControl, trdControl});
            if (fd == -1) {
                perror("SocketWaitRead");
                break;
            }

            if (fd == 0) {
                perror("TSocketWaitRead Timeout");
                break;
            }

            rcvsz = SockRead(fd, buf, sizeof(buf));
            if (rcvsz < 0) {
                perror("SockRead");
                break;
            }

            if (rcvsz == 0) {
                // Continue to listen if the trdControl server close the incoming connection
                //because some applications maybe establish short connections multiple times in succession
                //Example: http1.0
                flag = fd == iSControl;
                break;
            }

            wrtsz = SockWrite(fd == iSControl ? trdControl : iSControl, buf, rcvsz);
            if (wrtsz != rcvsz) {
                perror("SockWrite");
                break;
            }
        }

        SockClose(trdControl);
        if (flag) {
            SockClose(_);
            goto end;
        }
    }

end:
    return;
}

void SocksServer::ConnectV5(int iSControl, S5CHeader *cHeader)
{
    int trdControl {-1};
    sockaddr_in sIn;
    sockaddr_in6 sIn6;
    socklen_t sInLen;

    int fd;
    int recvLen;
    int wrtLen;
    char buf[1024]{0, };
    S5SHeader* sHeader = (S5SHeader*)buf;

    if (0x01 == cHeader->addrType) {
        trdControl = connTo(cHeader->getPort(), cHeader->getIPV4Addr());
    } else if (0x03 == cHeader->addrType) {
        memcpy(buf, cHeader->getDomainName(), cHeader->getDomainLength());
        hostent* htent = gethostbyname2(buf, AF_INET);
        if (nullptr != htent) {
            uint32_t ipv4addr;
            int idx {0};
            while (nullptr != htent->h_addr_list[idx]) {
                memcpy(&ipv4addr, htent->h_addr_list[idx], 4);
                trdControl = connTo(cHeader->getPort(), ipv4addr);
                if (-1 != trdControl) break;
                idx++;
            }
        }

        if (-1 == trdControl) {
            htent = gethostbyname2(buf, AF_INET6);
            if (nullptr != htent) {
                IPV6Addr ipv6addr;
                int idx {0};
                while (nullptr != htent->h_addr_list[idx]) {
                    memcpy(&ipv6addr, htent->h_addr_list[idx], 16);
                    trdControl = connTo(cHeader->getPort(), ipv6addr);
                    if (-1 != trdControl) break;
                    idx++;
                }
            }
        }

    } else if (0x04 == cHeader->addrType) {
        IPV6Addr ipv6addr;
        memcpy(&ipv6addr, cHeader->getIPV6Addr(), sizeof(IPV6Addr));
        trdControl = connTo(cHeader->getPort(), ipv6addr);
    } else {
        trdControl = -1;
    }

    sHeader->version = 0x05;
    sHeader->addrType = 0x01;

    if (-1 == trdControl) {
        sHeader->status = 0x01;
        if (0x01 == cHeader->addrType) {
            sHeader->setIPV4Addr(uint32_t{0x00});
        } else if (0x03 == cHeader->addrType) {
            sHeader->addrType = 0x03;
            sHeader->setDomainName(" ");
        } else if (0x04 == cHeader->addrType) {
            sHeader->addrType = 0x04;
            sHeader->setIPV6Addr(IPV6Addr{});
        } else {
            sHeader->setIPV4Addr(uint32_t{0x00});
        }
        sHeader->setPort(uint16_t{0x00});

        SockWrite(iSControl, sHeader, sHeader->getTotalLength());
        goto end;
    }

    if (0x01 == cHeader->addrType || 0x03 == cHeader->addrType) {
        sHeader->addrType = cHeader->addrType;
        sInLen = sizeof(sockaddr_in);
        if (0 != getsockname(trdControl, (sockaddr*)&sIn, &sInLen)) {
            SockClose(trdControl);
            sHeader->status = 0x01;

            if (0x01 == cHeader->addrType) sHeader->setIPV4Addr(uint32_t{0x00});
            else sHeader->setDomainName("");

            sHeader->setPort(uint16_t{0x00});

            SockWrite(iSControl, sHeader, sHeader->getTotalLength());
            goto end;
        }

        //let the socks5 client to convert ipv4 0.0.0.0 to the appropriate address which is used to connect to server,
        //to avoid some error condition that socks server is inside of a NAT network
        if (0x01 == cHeader->addrType) sHeader->setIPV4Addr(uint32_t{0x00});
        else sHeader->setDomainName("");

        sHeader->setPort(sIn.sin_port);
    } else if (0x04 == cHeader->addrType){
        sHeader->addrType = 0x04;
        sInLen = sizeof(sockaddr_in6);
        if (0 != getsockname(trdControl, (sockaddr*)&sIn6, &sInLen)) {
            SockClose(trdControl);
            sHeader->status = 0x01;
            sHeader->setIPV6Addr(IPV6Addr{0x00});
            sHeader->setPort(uint16_t{0x00});

            SockWrite(iSControl, sHeader, sHeader->getTotalLength());
            goto end;
        }

        IPV6Addr ipv6addr;
        memcpy(&ipv6addr, &sIn6.sin6_addr, sizeof(IPV6Addr));
        sHeader->setIPV6Addr(ipv6addr);
        sHeader->setPort(sIn6.sin6_port);
    }

    sHeader->status = 0x00;

    SockWrite(iSControl, sHeader, sHeader->getTotalLength());

    while (true) {
        fd = MARKTOOLS::SocketWaitRead(tv, {iSControl, trdControl});
        if (fd == 0) {
            SockClose(trdControl);
            goto end;
        }

        if (fd < 0) {
            SockClose(trdControl);
            perror("SocketWaitRead");
            goto end;
        }

        recvLen = SockRead(fd, buf, sizeof(buf));
        if (0 == recvLen) {
            SockClose(trdControl);
            goto end;
        }

        if (-1 == recvLen) {
            SockClose(trdControl);
            perror("SockRead");
            goto end;
        }

        wrtLen = SockWrite(fd == iSControl ? trdControl : iSControl, buf, recvLen);
        if (wrtLen != recvLen) {
            SockClose(trdControl);
            perror("SockWrite");
            goto end;
        }
    }

end:
    return;
}

void SocksServer::BindV5(int iSControl, const S5CHeader *s5CHeader, const sockaddr_in &iCSIn)
{

}

void SocksServer::addSession(const std::string &iHstDotPort, const std::map<std::string, Variant> &iV)
{
    std::lock_guard<std::mutex> lk(mSsonMapMtx);
    mSessionMap[iHstDotPort] = iV;
}

void SocksServer::removeSession(const std::string &iHstDotPort)
{
    std::lock_guard<std::mutex> lk(mSsonMapMtx);
    mSessionMap.erase(iHstDotPort);
}

std::map<std::string, Variant> SocksServer::getSession(const std::string &iHstDotPort)
{
    std::lock_guard<std::mutex> lk(mSsonMapMtx);
    if (mSessionMap.end() == mSessionMap.find(iHstDotPort)) return std::map<std::string, Variant>();

    return mSessionMap[iHstDotPort];
}
