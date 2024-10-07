#include "synflood-application.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("SynFloodApplication");

NS_OBJECT_ENSURE_REGISTERED (SynFloodApplication);

SynFloodApplication::SynFloodApplication()
    : m_serverPort(0)
{
}

SynFloodApplication::~SynFloodApplication()
{
}

void SynFloodApplication::Setup(Ipv4Address serverAddress, uint16_t serverPort, bool flood)
{
    m_serverAddress = serverAddress;
    m_serverPort = serverPort;
    m_flood = flood;
    m_random = CreateObject<UniformRandomVariable>();
    m_random->SetAttribute("Min", DoubleValue(1.0));
    m_random->SetAttribute("Max", DoubleValue(20.0));
}

void SynFloodApplication::StartApplication(void)
{
m_socket = Socket::CreateSocket(GetNode(), TypeId::LookupByName("ns3::Ipv4RawSocketFactory"));
m_socket->SetAttribute("Protocol", UintegerValue(6));
if (m_flood == true){
    m_sendEvent = Simulator::Schedule(Seconds(0.0), &SynFloodApplication::SendSynPacketFlooding, this);
} else{
    m_sendEvent = Simulator::Schedule(Seconds(0.0), &SynFloodApplication::SendSynPacket, this);
}

m_socket->Bind();
m_socket->Connect(InetSocketAddress(m_serverAddress, m_serverPort));
}

void SynFloodApplication::StopApplication(void)
{
    Simulator::Cancel(m_sendEvent);
    if (m_socket)
    {
        m_socket->Close();
    }
}

void SynFloodApplication::SendSynPacketFlooding()
{

    // Create TCP header with SYN flag
    TcpHeader tcpHeader;
    tcpHeader.SetSourcePort(m_random->GetValue(1024, 65535)); // Random source port
    tcpHeader.SetDestinationPort(m_serverPort);
    tcpHeader.SetFlags(TcpHeader::SYN);

    // Create packet
    Ptr<Packet> packet = Create<Packet>(512); // Empty payload
    packet->AddHeader(tcpHeader);
    // packet->AddHeader(ipHeader);
    // packet->AddHeader(ethHeader);

    // Send packet
    m_socket->Send(packet);

    // Schedule next SYN packet
    m_sendEvent = Simulator::Schedule(NanoSeconds(1600), &SynFloodApplication::SendSynPacketFlooding, this); //3 Kbps
}

void SynFloodApplication::SendSynPacket()
{

    // Create TCP header with SYN flag
    TcpHeader tcpHeader;
    tcpHeader.SetSourcePort(m_random->GetValue(1024, 65535)); // Random source port
    tcpHeader.SetDestinationPort(m_serverPort);
    tcpHeader.SetFlags(TcpHeader::SYN);

    // Create packet
    Ptr<Packet> packet = Create<Packet>(512); // Empty payload
    packet->AddHeader(tcpHeader);
    // packet->AddHeader(ipHeader);
    // packet->AddHeader(ethHeader);

    // Send packet
    m_socket->Send(packet);

    // Schedule next SYN packet
    m_sendEvent = Simulator::Schedule(Seconds(3), &SynFloodApplication::SendSynPacket, this);
}
}
