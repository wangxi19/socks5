#ifndef SOCKS5SERVER_H
#define SOCKS5SERVER_H
#include <stdint.h>
#include <map>
#include <variant>
#include <mutex>
#include <string.h>

struct IPV6Addr {
    uint32_t field1{0, };
    uint32_t field2{0, };
    uint32_t field3{0, };
    uint32_t field4{0, };
};
typedef std::variant<uint16_t, uint32_t, std::string, IPV6Addr> Variant;
struct sockaddr_in;

class SocksServer
{
public:
    //socks4 client's header format
    struct S4CHeader {
    public:
        uint8_t version{0x04};
        /**
              0x01: establish a TCP/IP stream connection
              0x02: establish a TCP/IP port binding (such as FTP port mode,
                    client need to listenning a port)
            */
        uint8_t cmdCode{0x00};
        uint16_t portNum{0x0000};
        uint32_t ipaddr{0x000000};
        char userId[1]{0, };

        inline const char* getUserId() {
            return userId;
        }
    };

    //socks4 server's header format
    struct S4SHeader {
    private:
        //must be null byte
        uint8_t version{0x00};
    public:
        /**
            0x5A: request granted
            0x5B: request rejected or failed
            0x5C: request failed because client is not running identd
                  (or not reachable from the server)
            0x5D: request failed because client's identd could not confirm the
                  user ID string in the request
        */
        uint8_t status{0x00};
        //2 arbitrary bytes, which should be ignored
        uint16_t dstPort{0x0000};
        //4 arbitrary bytes, which should be ignored
        uint32_t dstIp{0x00000000};
    };


    //socks5
    //supported authentication methods
    char authMethodsLst[1] {
        0x00
        //todo, add other auth methods
    };

    struct S5CHeader
    {
        uint8_t version{0x05};
        //0x01: establish a tcp/ip stream connection
        //0x02: establish a tcp/ip port binding
        //0x03: associate a udp port
        uint8_t cmd{0x00};
        uint8_t reserved{0x00};
        //0x01: IPV4
        //0x03: Domain name
        //0x04: IPV6
        uint8_t addrType{0x00};
        char destAddr[1] {0x00};
        //Call the function must wait for receiving length was reached sizeof S5CHeader
        inline size_t getTotalLength() {
            if (0x01 == addrType) {
                return sizeof(S5CHeader) + 3 + 2;
            }

            if (0x03 == addrType) {
                return sizeof(S5CHeader) + (size_t)destAddr[0] + 2;
            }

            if (0x04 == addrType) {
                return sizeof(S5CHeader) + 15 + 2;
            }
        }

        inline uint32_t getIPV4Addr() {
            if (0x01 != addrType) return 0;

            uint32_t ipv4addr;
            memcpy(&ipv4addr, destAddr, 4);
            return ipv4addr;
        }

        inline const char* getDomainName() {
            if (0x03 != addrType) return 0;

            return destAddr + 1;
        }

        inline size_t getDomainLength() {
            if (0x03 != addrType) return 0;

            return size_t(destAddr[0]);
        }

        inline const IPV6Addr* getIPV6Addr() {
            return (IPV6Addr*)&destAddr;
        }

        inline uint16_t getPort() {
            uint16_t portNum{0};
            if (0x01 == addrType) {
                memcpy(&portNum, destAddr + 4, 2);
            } else if (0x03 == addrType) {
                memcpy(&portNum, destAddr + 1 + size_t(destAddr[0]), 2);
            } else if (0x04 == addrType) {
                memcpy(&portNum, destAddr + 16, 2);
            }

            return portNum;
        }
    };

    struct S5SHeader
    {
        uint8_t version{0x05};
        //0x00: request granted
        //0x01: general failure
        //0x02: connection not allowed by ruleset
        //0x03: network unreachable
        //0x04: host unreachable
        //0x05: connection refused by destination host
        //0x06: TTL expired
        //0x07: command not supported / protocol error
        //0x08: address type not supported
        uint8_t status{0x00};
        uint8_t reserved{0x00};
        uint8_t addrType{0x00};

        char destAddr[1] {0x00};
        //Call the function must wait for receiving length was reached sizeof S5CHeader
        inline size_t getTotalLength() {
            if (0x01 == addrType) {
                return sizeof(S5CHeader) + 3 + 2;
            }

            if (0x03 == addrType) {
                return sizeof(S5CHeader) + (size_t)destAddr[0] + 2;
            }

            if (0x04 == addrType) {
                return sizeof(S5CHeader) + 15 + 2;
            }
        }

        inline uint32_t getIPV4Addr() {
            if (0x01 != addrType) return 0;

            uint32_t ipv4addr;
            memcpy(&ipv4addr, destAddr, 4);
            return ipv4addr;
        }

        inline void setIPV4Addr(const uint32_t& ipV4Addr) {
            if (0x01 != addrType) return;

            memcpy(destAddr, &ipV4Addr, 4);
            return;
        }

        inline const char* getDomainName() {
            if (0x03 != addrType) return 0;

            return destAddr + 1;
        }

        inline void setDomainName(const char* domain) {
            if (0x03 != addrType) return;

            if (strlen(domain) > 255) return;

            destAddr[0] = char(strlen(domain));
            memcpy(destAddr + 1, domain, strlen(domain));
        }

        inline size_t getDomainLength() {
            if (0x03 != addrType) return 0;

            return size_t(destAddr[0]);
        }

        inline const IPV6Addr* getIPV6Addr() {
            if (0x04 != addrType) return nullptr;

            return (IPV6Addr*)&destAddr;
        }

        inline void setIPV6Addr(const IPV6Addr& ipV6Addr) {
            if (0x04 != addrType) return;

            memcpy(destAddr, &ipV6Addr, 16);
        }

        inline uint16_t getPort() {
            uint16_t portNum{0};
            if (0x01 == addrType) {
                memcpy(&portNum, destAddr + 4, 2);
            } else if (0x03 == addrType) {
                memcpy(&portNum, destAddr + 1 + size_t(destAddr[0]), 2);
            } else if (0x04 == addrType) {
                memcpy(&portNum, destAddr + 16, 2);
            }

            return portNum;
        }

        inline void setPort(const uint16_t& port) {
            if (0x01 == addrType) {
                memcpy(destAddr + 4, &port, 2);
            } else if (0x03 == addrType) {
                memcpy(destAddr + 1 + (size_t)destAddr[0], &port, 2);
            } else if (0x04 == addrType) {
                memcpy(destAddr + 16, &port, 2);
            }

            return;
        }
    };

public:
    explicit SocksServer();
    int listenning(uint16_t iPort = 1080, const char* iAddr = "0.0.0.0");

private:
    void distributor(int iSControl, const sockaddr_in &iCSIn);
    void serveV4(int iSControl, const sockaddr_in &iCSIn);
    void serveV5(int iSControl, const sockaddr_in &iCSIn);
    void greetingV5(int iSControl, const sockaddr_in &iCSIn);
    inline int connTo(uint16_t iPort, uint32_t iAddr);
    inline int connTo(uint16_t iPort, const IPV6Addr& iAddr);
    inline int bindOn(uint16_t iPort = 0, uint32_t iAddr = 0);
    inline int bindOn(uint16_t iPort, const IPV6Addr& iAddr);

    void ConnectV4(int iSControl, uint16_t iPort, uint32_t iAddr);
    void BindV4(int iSControl, uint16_t iPort, uint32_t iAddr, const std::string& iUsrId, const sockaddr_in &iCSIn);

    void ConnectV5(int iSControl, S5CHeader* cHeader);
    void BindV5(int iSControl, const S5CHeader* s5CHeader, const sockaddr_in &iCSIn);


    void addSession(const std::string& iHstDotPort, const std::map<std::string, Variant>& iV);
    void removeSession(const std::string& iHstDotPort);
    std::map<std::string, Variant> getSession(const std::string& iHstDotPort);
private:
    //the default port number is 1080
    uint16_t lstPort{0x0438};
    //the default address is 0.0.0.0
    uint32_t lstAddr{0x00000000};

    std::map<std::string, std::map<std::string, Variant> > mSessionMap;
    std::mutex mSsonMapMtx;
    timeval tv;
};

#endif // SOCKS5SERVER_H
