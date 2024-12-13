#include <iostream>
#include <fstream>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/v1model-p4-pipeline.h"
#include "ns3/v1model-p4-queue.h"
#include "ns3/ethernet-header.h"
#include "ns3/ethernet-trailer.h"
#include "ns3/random-variable-stream.h"
#include "ns3/socket.h"
#include "ns3/traffic-control-helper.h"
#include "ns3/point-to-point-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("Coremelt");

std::string outPcap = "trace-data/coremelt/";
std::string suffix = "fifo";
// Open log file for writing
std::ofstream logFile(outPcap+"packet_log.txt");

void LogReceivedPackets(Ptr<PacketSink> sinkApp, std::ofstream &logFile, double interval) {
    static uint64_t lastRxCount = 0;
    uint64_t currentRxCount = sinkApp->GetTotalRx();
    uint64_t packetsReceivedInInterval = (currentRxCount - lastRxCount);
    lastRxCount = currentRxCount;

    // Log the packet count to the file
    logFile << Simulator::Now().GetSeconds() << " " << packetsReceivedInInterval << std::endl;

    // Schedule the next log
    Simulator::Schedule(Seconds(interval), &LogReceivedPackets, sinkApp, std::ref(logFile), interval);
}


void StartFlows(NodeContainer serverNodes, NodeContainer clientNodes, Ipv4InterfaceContainer routerServerInterfaces)
{
    // Create TCP flows from client to each server
    for (uint32_t i = 0; i < serverNodes.GetN(); ++i)
    {
        for (uint32_t j = 0; j < clientNodes.GetN(); ++j)
        {
            for (uint16_t port = 8080; port < 8090; ++port)
            {
                uint16_t p = port + 10*(i+j); 
                // Install PacketSink on each server (to act as TCP receiver)
                Address serverAddress(InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), p));
                PacketSinkHelper sinkHelper("ns3::TcpSocketFactory", serverAddress);
                ApplicationContainer serverApp = sinkHelper.Install(serverNodes.Get(i));
                serverApp.Start(Seconds(1.0));

                // Install TCP OnOff client on the client node (to act as TCP sender)
                BulkSendHelper clientHelper("ns3::TcpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), p));
            
                ApplicationContainer clientApp = clientHelper.Install(clientNodes.Get(j));
                clientApp.Start(Seconds(2.0));  // Start each flow with a slight delay

                // Schedule periodic logging
                // Ptr<PacketSink> sinkApp = DynamicCast<PacketSink>(serverApp.Get(0));
                // Simulator::Schedule(Seconds(1.0), &LogReceivedPackets, sinkApp, std::ref(logFile), 1.0);
            }
        }
    }
}

void StartCoremeltAttack(NodeContainer serverNodes, NodeContainer clientNodes, Ipv4InterfaceContainer routerServerInterfaces, int startPort = 1000)
{
    // Create a lot of supersmall flows from client to each server -> we congest the endlink
    for (uint32_t i = 0; i < serverNodes.GetN(); ++i)
    {
        for (uint32_t j = 0; j < clientNodes.GetN(); ++j)
        {
            for (uint16_t port = startPort; port < startPort+1000; ++port)
            {
                uint16_t p = port + 1000*(i+j); 
                // Install PacketSink on each server (to act as TCP receiver)
                Address serverAddress(InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), p));
                PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", serverAddress);
                ApplicationContainer serverApp = sinkHelper.Install(serverNodes.Get(i));
                serverApp.Start(Seconds(1.0));
                serverApp.Stop(Seconds(45.0));

                // Install TCP OnOff client on the client node (to act as TCP sender)
                // BulkSendHelper clientHelper("ns3::UdpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), p));

                UdpClientHelper clientHelper(routerServerInterfaces.GetAddress(i + 1), p);
                // OnOffHelper clientHelper("ns3::UdpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(2), port));
                // clientHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
                // clientHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
                // clientHelper.SetAttribute("DataRate", DataRateValue(DataRate("5Kbps")));
            
                ApplicationContainer clientApp = clientHelper.Install(clientNodes.Get(j));
                clientApp.Start(Seconds(20.0));  // Start each flow with a slight delay
                clientApp.Stop(Seconds(45.0));
            }
        }
    }
}

void QueueSizeTrace(Ptr<Queue<Packet>> queue) {
    uint32_t currentSize = queue->GetNPackets();
    std::cout << "Queue size at " << Simulator::Now().GetSeconds() 
              << "s: " << currentSize << " packets" << std::endl;

    // Schedule the next trace
    Simulator::Schedule(Seconds(0.1), &QueueSizeTrace, queue);
}

void PacketDropCallback(Ptr<const Packet> packet) {
    std::cout << "Packet dropped at " << Simulator::Now().GetSeconds() << "s, packet size: " << packet->GetSize() << std::endl;
    
}

void UpdateCluster(){
    std::system("python3 /home/mininet/ns3-repos/ns-3-allinone/ns-3.29/src/bmv2-tools/controller.py");
    Simulator::Schedule(Seconds(0.1), &UpdateCluster);
}

int main(int argc, char *argv[])
{
    Time::SetResolution (Time::NS);
    Config::SetDefault("ns3::TcpL4Protocol::SocketType", StringValue("ns3::TcpWestwood"));
    bool p4Enabled = false;
    bool deprioEnabled = false;
    bool dropEnabled = false;
    bool accturboEnabled = false;
    bool lfaEnabled = false;
    
    CommandLine cmd;
    cmd.AddValue ("outPcap", "Simulation PCAP Destination folder", outPcap);
    cmd.AddValue ("p4Enabled", "Enable P4", p4Enabled);
    cmd.AddValue ("deprioEnabled", "Enable Deprioritization, Default FALSE", deprioEnabled);
    cmd.AddValue ("dropEnabled", "Enable Dropping, Default FALSE", dropEnabled);
    cmd.AddValue ("accturboEnabled", "Enable AccTurbo, Default FALSE", accturboEnabled);
    cmd.AddValue ("lfaEnabled", "Enable Link Flooding Attack", lfaEnabled);
    cmd.Parse (argc, argv);


    LogComponentEnable ("Coremelt", LOG_LEVEL_INFO);
    Packet::EnablePrinting ();
    // Create nodes
    Ptr<Node> routerNode1 = CreateObject<Node> ();
    Ptr<Node> routerNode2 = CreateObject<Node> ();
    
    NodeContainer serverNodes1, serverNodes2, serverNodes3, serverNodes4, serverNodes5, serverNodes6,
                  serverNodes7, serverNodes8, serverNodes9, serverNodes10, serverNodes11, serverNodes12;
    serverNodes1.Create(6);
    serverNodes2.Create(6);
    serverNodes3.Create(6);
    serverNodes4.Create(6);
    serverNodes5.Create(6);
    serverNodes6.Create(6);
    serverNodes7.Create(6);
    serverNodes8.Create(6);
    serverNodes9.Create(6);
    serverNodes10.Create(6);
    serverNodes11.Create(6);
    serverNodes12.Create(6);

    // Create a CSMA network (Client -> Router -> Servers)
    NodeContainer routerToServers1, routerToServers2, routerToServers3, routerToServers4, routerToServers5, routerToServers6,
                  routerToServers7, routerToServers8, routerToServers9, routerToServers10, routerToServers11, routerToServers12;    
    routerToServers1.Add(routerNode1);
    routerToServers1.Add(serverNodes1);
    routerToServers2.Add(routerNode1);
    routerToServers2.Add(serverNodes2);
    routerToServers3.Add(routerNode1);
    routerToServers3.Add(serverNodes3);
    routerToServers4.Add(routerNode2);
    routerToServers4.Add(serverNodes4);
    routerToServers5.Add(routerNode2);
    routerToServers5.Add(serverNodes5);
    routerToServers6.Add(routerNode2);
    routerToServers6.Add(serverNodes6);
    routerToServers7.Add(routerNode2);
    routerToServers7.Add(serverNodes7);
    routerToServers8.Add(routerNode2);
    routerToServers8.Add(serverNodes8);
    routerToServers9.Add(routerNode2);
    routerToServers9.Add(serverNodes9);
    routerToServers10.Add(routerNode2);
    routerToServers10.Add(serverNodes10);
    routerToServers11.Add(routerNode2);
    routerToServers11.Add(serverNodes11);
    routerToServers12.Add(routerNode2);
    routerToServers12.Add(serverNodes12);


    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
    p2p.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    // Setup CSMA attributes
    CsmaHelper lcsma;
    lcsma.SetChannelAttribute("DataRate", StringValue("500Kbps"));
    lcsma.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    // Setup CSMA attributes
    CsmaHelper rcsma;
    rcsma.SetChannelAttribute("DataRate", StringValue("500Kbps"));
    rcsma.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    // Install CSMA devices on the nodes
    NetDeviceContainer router1Router2Devices = p2p.Install(NodeContainer(routerNode1, routerNode2));
    NetDeviceContainer routerServerDevices1 = lcsma.Install(routerToServers1);
    NetDeviceContainer routerServerDevices2 = lcsma.Install(routerToServers2);
    NetDeviceContainer routerServerDevices3 = lcsma.Install(routerToServers3);
    NetDeviceContainer routerServerDevices4 = rcsma.Install(routerToServers4);
    NetDeviceContainer routerServerDevices5 = rcsma.Install(routerToServers5);
    NetDeviceContainer routerServerDevices6 = rcsma.Install(routerToServers6);
    NetDeviceContainer routerServerDevices7 = rcsma.Install(routerToServers7);
    NetDeviceContainer routerServerDevices8 = rcsma.Install(routerToServers8);
    NetDeviceContainer routerServerDevices9 = rcsma.Install(routerToServers9);
    NetDeviceContainer routerServerDevices10 = rcsma.Install(routerToServers10);
    NetDeviceContainer routerServerDevices11 = rcsma.Install(routerToServers11);
    NetDeviceContainer routerServerDevices12 = rcsma.Install(routerToServers12);

    Ptr<NetDevice> r1Device = router1Router2Devices.Get (0);
    Ptr<NetDevice> r2Device = router1Router2Devices.Get (1);

    // Set up a queue with a maximum of 10 packets
    if (p4Enabled == false){
        Ptr<PointToPointNetDevice> device = DynamicCast<PointToPointNetDevice>(router1Router2Devices.Get(0));
        Ptr<Queue<Packet>> queue = device->GetQueue();
        queue->SetAttribute("MaxSize", QueueSizeValue(QueueSize(QueueSizeUnit::PACKETS, 4)));

        Ptr<PointToPointNetDevice> device2 = DynamicCast<PointToPointNetDevice>(router1Router2Devices.Get(1));
        Ptr<Queue<Packet>> queue2 = device2->GetQueue();
        queue2->SetAttribute("MaxSize", QueueSizeValue(QueueSize(QueueSizeUnit::PACKETS, 4)));
    }

    // Install Internet stack on all nodes
    InternetStackHelper internet;
    internet.Install(routerNode1);
    internet.Install(routerNode2);
    internet.Install(serverNodes1);
    internet.Install(serverNodes2);
    internet.Install(serverNodes3);
    internet.Install(serverNodes4);
    internet.Install(serverNodes5);
    internet.Install(serverNodes6);
    internet.Install(serverNodes7);
    internet.Install(serverNodes8);
    internet.Install(serverNodes9);
    internet.Install(serverNodes10);
    internet.Install(serverNodes11);
    internet.Install(serverNodes12);

    if (p4Enabled){
        NS_LOG_INFO ("Configure Tracing.");
    }

    // Assign IP addresses
    // Client and router
    Ipv4AddressHelper address;

    address.SetBase("10.0.0.0", "255.255.255.0");  // Client and Router subnet
    Ipv4InterfaceContainer router1Router2Interfaces = address.Assign(router1Router2Devices);
    
    // Router and servers
    address.SetBase("10.1.1.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces1 = address.Assign(routerServerDevices1);

    // Router and servers
    address.SetBase("10.1.2.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces2 = address.Assign(routerServerDevices2);

    // Router and servers
    address.SetBase("10.1.3.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces3 = address.Assign(routerServerDevices3);

    // Router and servers
    address.SetBase("192.168.1.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces4 = address.Assign(routerServerDevices4);

    // Router and servers
    address.SetBase("192.168.2.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces5 = address.Assign(routerServerDevices5);

    // Router and servers
    address.SetBase("192.168.3.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces6 = address.Assign(routerServerDevices6);

    // Router and servers
    address.SetBase("192.168.4.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces7 = address.Assign(routerServerDevices7);

    // Router and servers
    address.SetBase("192.168.5.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces8 = address.Assign(routerServerDevices8);

    // Router and servers
    address.SetBase("192.168.6.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces9 = address.Assign(routerServerDevices9);

    // Router and servers
    address.SetBase("192.168.7.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces10 = address.Assign(routerServerDevices10);

    // Router and servers
    address.SetBase("192.168.8.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces11 = address.Assign(routerServerDevices11);

    // Router and servers
    address.SetBase("192.168.9.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces12 = address.Assign(routerServerDevices12);



    Ptr<Ipv4> ipv4Router = routerNode1->GetObject<Ipv4>();
    ipv4Router->SetAttribute("IpForward", BooleanValue(true));

    Ptr<Ipv4> ipv4Router2 = routerNode2->GetObject<Ipv4>();
    ipv4Router2->SetAttribute("IpForward", BooleanValue(true));

    // Start TCP flows
    StartFlows(serverNodes1, serverNodes4, routerServerInterfaces1);

    if(lfaEnabled){
        StartCoremeltAttack(serverNodes2, serverNodes5, routerServerInterfaces2, 1000);
        StartCoremeltAttack(serverNodes2, serverNodes7, routerServerInterfaces2, 8000);
        // StartCoremeltAttack(serverNodes2, serverNodes8, routerServerInterfaces2, 15000);
        // StartCoremeltAttack(serverNodes2, serverNodes9, routerServerInterfaces2, 22000);
        StartCoremeltAttack(serverNodes3, serverNodes10, routerServerInterfaces3, 1000);
        StartCoremeltAttack(serverNodes3, serverNodes11, routerServerInterfaces3, 8000);
        // StartCoremeltAttack(serverNodes3, serverNodes12, routerServerInterfaces3, 15000);

    }

    // csma.EnablePcapAll(outPcap+"/packets");  // Trace packets on server side
    p2p.EnablePcap(outPcap+suffix, r2Device, true);
    NS_LOG_INFO ("PCAP packets will be written in folder: " << outPcap);
    
    // Enable routing globally
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();



    // Run the simulation
    Simulator::Stop(Seconds(90));

    // Run simulation
    Simulator::Run();

    // Close log file
    // logFile.close();

    Simulator::Destroy();

    return 0;
}
