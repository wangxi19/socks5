#ifndef SOCKS5SERVER_H
#define SOCKS5SERVER_H
#include <stdint.h>
#include <map>
#include <variant>
#include <mutex>

typedef std::variant<uint16_t, uint32_t, std::string> Variant;

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
        const char* userId{nullptr};
    };

    //socks4 server's header format
    struct S4SHeader {
    private:
        //must be null byte
        uint8_t reserved1{0x00};
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
        uint16_t reserved2{0x0000};
        //4 arbitrary bytes, which should be ignored
        uint32_t reserved3{0x00000000};
    };

public:
    explicit SocksServer();
    int listenning(uint16_t iPort = 1080, const char* iAddr = "0.0.0.0");

private:
    void serve(int iSControl, const sockaddr_in &iCSIn);
    inline int connTo(uint16_t iPort, uint32_t iAddr);

    void Connect(int iSControl, uint16_t iPort, uint32_t iAddr);
    void Bind(int iSControl, uint16_t iPort, uint32_t iAddr, const std::string& iUsrId, const sockaddr_in &iCSIn);

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
};

#endif // SOCKS5SERVER_H
