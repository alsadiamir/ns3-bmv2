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

NS_LOG_COMPONENT_DEFINE ("ACCTurboFig7b");


void StartFlows(NodeContainer serverNodes, Ptr<Node> clientNode, Ipv4InterfaceContainer routerServerInterfaces)
{
    // Create TCP flows from client to each server
    uint16_t port = 8080;
    for (uint32_t i = 0; i < serverNodes.GetN(); ++i)
    {
        // Install PacketSink on each server (to act as TCP receiver)
        Address serverAddress(InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), port));
        PacketSinkHelper sinkHelper("ns3::TcpSocketFactory", serverAddress);
        ApplicationContainer serverApp = sinkHelper.Install(serverNodes.Get(i));
        serverApp.Start(Seconds(1.0));

        BulkSendHelper clientHelper("ns3::TcpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), port));

        ApplicationContainer clientApp = clientHelper.Install(clientNode);
        clientApp.Start(Seconds(2.0 + i));  // Start each flow with a slight delay
    }
}

void StartVolumetricFlow(NodeContainer serverNodes, Ptr<Node> clientNode, Ipv4InterfaceContainer routerServerInterfaces)
{
    // Create TCP flows from client to each server
    uint16_t port = 2150;
    uint32_t naddr = 100;

    Address serverAddress(InetSocketAddress(routerServerInterfaces.GetAddress(naddr), port));
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", serverAddress);
    ApplicationContainer serverApp = sinkHelper.Install(serverNodes.Get(naddr-1));
    serverApp.Start(Seconds(0.0));
    // Install TCP OnOff client on the client node (to act as TCP sender)
    OnOffHelper clientHelper("ns3::UdpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(naddr), port));
    clientHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    clientHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    clientHelper.SetAttribute("DataRate", DataRateValue(DataRate("9.9Mbps")));  // Data rate

    ApplicationContainer clientApp = clientHelper.Install(clientNode);
    clientApp.Start(Seconds(20.0));  // Start each flow with a slight delay

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

void QueueSizeCallback(uint32_t oldSize, uint32_t newSize) {
    NS_LOG_UNCOND("Queue size changed: " << oldSize << " -> " << newSize);
}

void UpdateCluster(){
    std::system("python3 /home/mininet/ns3-repos/ns-3-allinone/ns-3.29/src/bmv2-tools/controller.py --thrift-port 9090");
    Simulator::Schedule(Seconds(0.1), &UpdateCluster);
}

int main(int argc, char *argv[])
{
    Time::SetResolution (Time::NS);
    Config::SetDefault("ns3::TcpL4Protocol::SocketType", StringValue("ns3::TcpWestwood"));
    std::string outPcap = "trace-data/fig7b/";
    std::string suffix = "fifo";
    bool accturboEnabled = false;
    
    CommandLine cmd;
    cmd.AddValue ("outPcap", "Simulation PCAP Destination folder", outPcap);
    cmd.AddValue ("accturboEnabled", "Enable AccTurbo, Default FALSE", accturboEnabled);
    cmd.Parse (argc, argv);


    LogComponentEnable ("ACCTurboFig7b", LOG_LEVEL_INFO);
    Packet::EnablePrinting ();
    // Create nodes
    Ptr<Node> clientNode = CreateObject<Node> ();
    Ptr<Node> attackerNode = CreateObject<Node> ();
    Ptr<Node> routerNode1 = CreateObject<Node> ();
    Ptr<Node> routerNode2 = CreateObject<Node> ();
    Ptr<Node> routerNode3 = CreateObject<Node> ();
    // Ptr<Node> routerNode4 = CreateObject<Node> ();
    
    NodeContainer serverNodes1, serverNodes2, serverNodes3, serverNodes4, serverNodes5, serverNodes6, serverNodesAtk;
    serverNodes1.Create(100);  // 6 Servers
    serverNodes2.Create(100);  // 6 Servers
    serverNodes3.Create(100);  // 6 Servers
    serverNodes4.Create(100);  // 6 Servers
    serverNodes5.Create(100);  // 6 Servers
    serverNodes6.Create(100);  // 6 Servers
    serverNodesAtk.Create(120);  // 6 Servers

    // Create a CSMA network (Client -> Router -> Servers)
    NodeContainer routerToServers1, routerToServers2, routerToServers3, routerToServers4, routerToServers5, routerToServers6, routerToServersAtk;
    routerToServers1.Add(routerNode3);
    routerToServers1.Add(serverNodes1);
    routerToServers2.Add(routerNode3);
    routerToServers2.Add(serverNodes2);
    routerToServers3.Add(routerNode3);
    routerToServers3.Add(serverNodes3);
    routerToServers4.Add(routerNode3);
    routerToServers4.Add(serverNodes4);
    routerToServers5.Add(routerNode3);
    routerToServers5.Add(serverNodes5);
    routerToServers6.Add(routerNode3);
    routerToServers6.Add(serverNodes6);
    routerToServersAtk.Add(routerNode3);
    routerToServersAtk.Add(serverNodesAtk);


    PointToPointHelper p2pc;
    p2pc.SetDeviceAttribute("DataRate", StringValue("800Kbps"));
    p2pc.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    PointToPointHelper p2pa;
    p2pa.SetDeviceAttribute("DataRate", StringValue("9.9Mbps"));
    p2pa.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));
    

    PointToPointHelper p2p2;
    p2p2.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
    p2p2.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    // Setup CSMA attributes
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("1Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    // Install CSMA devices on the nodes
    NetDeviceContainer clientRouterDevices = p2pc.Install(NodeContainer(clientNode, routerNode1));
    NetDeviceContainer attackerRouterDevices = p2pa.Install(NodeContainer(attackerNode, routerNode1));
    NetDeviceContainer router1Router2Devices = p2p2.Install(NodeContainer(routerNode1, routerNode2));
    NetDeviceContainer router2Router3Devices = p2p2.Install(NodeContainer(routerNode2, routerNode3));
    NetDeviceContainer routerServerDevices1 = csma.Install(routerToServers1);
    NetDeviceContainer routerServerDevices2 = csma.Install(routerToServers2);
    NetDeviceContainer routerServerDevices3 = csma.Install(routerToServers3);
    NetDeviceContainer routerServerDevices4 = csma.Install(routerToServers4);
    NetDeviceContainer routerServerDevices5 = csma.Install(routerToServers5);
    NetDeviceContainer routerServerDevices6 = csma.Install(routerToServers6);
    NetDeviceContainer routerServerDevicesAtk = csma.Install(routerToServersAtk);

    Ptr<NetDevice> rDevice = router1Router2Devices.Get (0);


    if(accturboEnabled == false){
        Ptr<PointToPointNetDevice> device = DynamicCast<PointToPointNetDevice>(router1Router2Devices.Get(0));
        Ptr<Queue<Packet>> queue = device->GetQueue();
        queue->SetAttribute("MaxSize", QueueSizeValue(QueueSize(QueueSizeUnit::PACKETS, 4)));
    }

    // Install Internet stack on all nodes
    InternetStackHelper internet;
    internet.Install(clientNode);
    internet.Install(attackerNode);
    internet.Install(routerNode1);
    internet.Install(routerNode2);
    internet.Install(routerNode3);
    internet.Install(serverNodes1);
    internet.Install(serverNodes2);
    internet.Install(serverNodes3);
    internet.Install(serverNodes4);
    internet.Install(serverNodes5);
    internet.Install(serverNodes6);
    internet.Install(serverNodesAtk);


    NS_LOG_INFO ("Configure Tracing.");

    if(accturboEnabled == true){    
        NS_LOG_INFO ("Accturbo Enabled.");
        Ptr<V1ModelP4Queue> customQueue2 = CreateObject<V1ModelP4Queue> ();
        std::string p4file = "src/traffic-control/examples/p4-src/detect_selfspec_p2p_2sw/detect_selfspec_p2p_2sw.json";
        std::string file = "src/traffic-control/examples/p4-src/detect_selfspec_p2p_2sw/anomaly.txt";
        customQueue2->SetAttribute("MaxQueueSize", UintegerValue(1));
        p4file = "src/traffic-control/examples/p4-src/accturbo/accturbo.json";
        file = "src/traffic-control/examples/p4-src/accturbo/setup_prio.txt";
        customQueue2->SetAttribute("DeprioritizationEnabled", BooleanValue(true));
        Simulator::Schedule(Seconds(0), &UpdateCluster);
        customQueue2->CreateP4Pipe (p4file, file);
        // customQueue2->SetOutPath(outPcap+"/second_sw.txt");
        Ptr<PointToPointNetDevice> p2pDevice2 = rDevice->GetObject<PointToPointNetDevice> ();
        p2pDevice2->SetQueue(customQueue2);
        suffix = "accturbo";
    }

    // Assign IP addresses
    // Client and router
    Ipv4AddressHelper address;
    address.SetBase("10.0.0.0", "255.255.255.0");  // Client and Router subnet
    Ipv4InterfaceContainer clientRouterInterfaces = address.Assign(clientRouterDevices);

    // Attacker and router
    address.SetBase("11.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer attackerRouterInterfaces = address.Assign(attackerRouterDevices);

    address.SetBase("10.1.0.0", "255.255.255.0");  // Client and Router subnet
    Ipv4InterfaceContainer router1Router2Interfaces = address.Assign(router1Router2Devices);

    address.SetBase("10.2.0.0", "255.255.255.0");
    Ipv4InterfaceContainer router2Router3Interfaces = address.Assign(router2Router3Devices);
    
    // Router and servers
    address.SetBase("160.15.33.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces1 = address.Assign(routerServerDevices1);

    // Router and servers
    address.SetBase("55.99.80.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces2 = address.Assign(routerServerDevices2);

    // Router and servers
    address.SetBase("240.1.77.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces3 = address.Assign(routerServerDevices3);

    // Router and servers
    address.SetBase("1.23.112.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces4 = address.Assign(routerServerDevices4);

    // Router and servers
    address.SetBase("111.2.66.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces5 = address.Assign(routerServerDevices5);

    // Router and servers
    address.SetBase("42.172.19.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces6 = address.Assign(routerServerDevices6);

    // // Router and servers
    address.SetBase("5.5.5.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfacesAtk = address.Assign(routerServerDevicesAtk);

    Ptr<Ipv4> ipv4Router = routerNode1->GetObject<Ipv4>();
    ipv4Router->SetAttribute("IpForward", BooleanValue(true));

    Ptr<Ipv4> ipv4Router2 = routerNode2->GetObject<Ipv4>();
    ipv4Router2->SetAttribute("IpForward", BooleanValue(true));

    Ptr<Ipv4> ipv4Router3 = routerNode3->GetObject<Ipv4>();
    ipv4Router3->SetAttribute("IpForward", BooleanValue(true));

    // Start TCP flows
    StartFlows(serverNodes1, clientNode, routerServerInterfaces1);
    StartFlows(serverNodes2, clientNode, routerServerInterfaces2);
    StartFlows(serverNodes3, clientNode, routerServerInterfaces3);
    StartFlows(serverNodes4, clientNode, routerServerInterfaces4);
    StartFlows(serverNodes5, clientNode, routerServerInterfaces5);
    StartFlows(serverNodes6, clientNode, routerServerInterfaces6);

    StartVolumetricFlow(serverNodesAtk, attackerNode, routerServerInterfacesAtk); //to keep same IP for analysis
    NS_LOG_INFO("Attack Enabled.");

    p2p.EnablePcap(outPcap+suffix, router1Router2Devices.Get(1), true);
    NS_LOG_INFO ("PCAP packets will be written in folder: " << outPcap);
    
    // Enable routing globally
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();



    // Run the simulation
    Simulator::Stop(Seconds(90));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
