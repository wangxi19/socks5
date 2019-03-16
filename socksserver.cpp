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

        serve(nControl, cSIn);
    }

    return 0;
}

void SocksServer::serve(int iSControl, const sockaddr_in &iCSIn)
{
    //read command from client
    timeval tv;
    tv.tv_sec = 20;
    tv.tv_usec = 0;
    char buf[1024] {0, };
    S4CHeader* cHeader = (S4CHeader*)buf;
    size_t offset{0};
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

    sHeader.reserved2 = (uint16_t)random();
    sHeader.reserved3 = (uint32_t)random();

    if (0x04 != cHeader->version || (0x01 != cHeader->cmdCode && 0x02 != cHeader->cmdCode)) {
        sHeader.status = 0x5B;
        SockWrite(iSControl, &sHeader, sizeof(S4SHeader));

        goto end;
    }

#ifdef _WIN32
    //todo, convert inet_ntoa to windows compatibility
#else
    addSession(std::string(inet_ntoa(iCSIn.sin_addr)) + ":" + std::to_string(iCSIn.sin_port),
               std::map<std::string, Variant>{
                   {std::string("DSTPORT"), Variant(cHeader->portNum)},
                   {std::string("DSTIP"), Variant(cHeader->ipaddr)},
                   {std::string("USERID"), Variant(std::string(cHeader->userId))}
               });
#endif

    //request to connect
    if (0x01 == cHeader->cmdCode) {
        Connect(iSControl, cHeader->portNum, cHeader->ipaddr);
    } else if (0x02 == cHeader->cmdCode) {
        Bind(iSControl, cHeader->portNum, cHeader->ipaddr, std::string(cHeader->userId), iCSIn);
    }

    end:
    SockClose(iSControl);
    removeSession(std::string(inet_ntoa(iCSIn.sin_addr)) + ":" + std::to_string(iCSIn.sin_port));
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

void SocksServer::Connect(int iSControl, uint16_t iPort, uint32_t iAddr)
{
    timeval tv;
    tv.tv_sec = 20;
    tv.tv_usec = 0;
    S4SHeader sHeader;
    sHeader.reserved2 = (uint16_t)random();
    sHeader.reserved3 = (uint32_t)random();
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

void SocksServer::Bind(int iSControl, uint16_t iPort, uint32_t iAddr, const std::string &iUsrId, const sockaddr_in &iCSIn)
{
    S4SHeader sHeader;

    auto sessionVal = getSession(std::string(inet_ntoa(iCSIn.sin_addr)) + ":" + std::to_string(iCSIn.sin_port));

    if (sessionVal.empty() ||
            iPort != std::get<uint16_t>(sessionVal["DSTPORT"]) ||
            iAddr != std::get<uint32_t>(sessionVal["DSTIP"]) ||
            iUsrId != std::get<std::string>(sessionVal["USERID"]))
    {
        sHeader.status = 0x5C;
        SockWrite(iSControl, &sHeader, sizeof(S4SHeader));
        goto end;
    }

    //todo
    //listenning a new port, then return self address (or 0.0.0.0) and the port to the client

    end:
    return;
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
