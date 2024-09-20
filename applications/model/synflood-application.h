#ifndef SYN_FLOOD_APPLICATION_H
#define SYN_FLOOD_APPLICATION_H

#include "ns3/internet-module.h"
#include "ns3/application.h"



namespace ns3 {
class SynFloodApplication : public Application
{
public:
    SynFloodApplication();
    virtual ~SynFloodApplication();

    void Setup(Ipv4Address serverAddress, uint16_t serverPort, bool flood);

protected:
    virtual void StartApplication(void);
    virtual void StopApplication(void);

    void SendSynPacketFlooding();
    void SendSynPacket();

private:
    Ipv4Address m_serverAddress;
    uint16_t m_serverPort;
    EventId m_sendEvent;
    Ptr<UniformRandomVariable> m_random;
    bool m_flood;
    Ptr<Socket> m_socket;
};


}
#endif /* SYN_FLOOD_APPLICATION_H */