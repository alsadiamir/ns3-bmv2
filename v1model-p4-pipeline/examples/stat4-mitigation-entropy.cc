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

NS_LOG_COMPONENT_DEFINE ("Stat4EntropyTracingExample");


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
        // serverApp.Stop(Seconds(simulationTime));

        // Install TCP OnOff client on the client node (to act as TCP sender)
        OnOffHelper clientHelper("ns3::TcpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), port));
        clientHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        clientHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        std::string dataRate = "50Kbps";
        clientHelper.SetAttribute("DataRate", DataRateValue(DataRate(dataRate)));  // Data rate
        clientHelper.SetAttribute("PacketSize", UintegerValue(1024));  // Packet size
        clientHelper.SetAttribute("MaxBytes", UintegerValue(250000)); // Max payload size in bytes
        // double totalBitsToSend = 2240 * 8;  // Convert bytes to bits
        // double rateInBps = atof(dataRate.c_str()) * 1e6;  // Convert Mbps to bps
        // double transmissionTime = totalBitsToSend / rateInBps;  // Transmission time in seconds

        ApplicationContainer clientApp = clientHelper.Install(clientNode);
        clientApp.Start(Seconds(2.0));  // Start each flow with a slight delay
        // clientApp.Stop(Seconds(2.0 + transmissionTime + 0.1*(i/36)));
        // StartBgSynApp(serverNodes.Get(i), clientNode, routerServerInterfaces, 2.0 + i);
    }
}

void StartVolumetricFlow(NodeContainer serverNodes, Ptr<Node> clientNode, Ipv4InterfaceContainer routerServerInterfaces)
{
    // Create TCP flows from client to each server
    // uint16_t port = 8081;
    for (int port = 2000; port<2200; port ++)
    { // Install PacketSink on each server (to act as TCP receiver)
        Address serverAddress(InetSocketAddress(routerServerInterfaces.GetAddress(2), port));
        PacketSinkHelper sinkHelper("ns3::TcpSocketFactory", serverAddress);
        ApplicationContainer serverApp = sinkHelper.Install(serverNodes.Get(1));
        serverApp.Start(Seconds(1.0));
        // serverApp.Stop(Seconds(simulationTime));

        // Install TCP OnOff client on the client node (to act as TCP sender)
        OnOffHelper clientHelper("ns3::TcpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(2), port));
        clientHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        clientHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        clientHelper.SetAttribute("DataRate", DataRateValue(DataRate("7.5Kbps")));  // Data rate
        clientHelper.SetAttribute("PacketSize", UintegerValue(1024));  // Packet size

        ApplicationContainer clientApp = clientHelper.Install(clientNode);
        clientApp.Start(Seconds(5.0));  // Start each flow with a slight delay
        clientApp.Stop(Seconds(15.0));
    }
}


void DropCallback(Ptr<const Packet> packet)
{
    NS_LOG_INFO("Packet dropped: " << packet->GetUid());
}

int main(int argc, char *argv[])
{
    std::string outPcap = "trace-data/entropy/withattack";
    bool p4Enabled = false;
    bool deprioEnabled = false;
    bool attackEnabled = false;
    
    CommandLine cmd;
    cmd.AddValue ("outPcap", "Simulation PCAP Destination folder", outPcap);
    cmd.AddValue ("p4Enabled", "Enable P4", p4Enabled);
    cmd.AddValue ("deprioEnabled", "Enable Deprioritization, Default DROP", deprioEnabled);
    cmd.AddValue ("attackEnabled", "Enable Attack", attackEnabled);
    cmd.Parse (argc, argv);

    LogComponentEnable ("Stat4EntropyTracingExample", LOG_LEVEL_INFO);
    Packet::EnablePrinting ();
    // Create nodes
    Ptr<Node> clientNode = CreateObject<Node> ();
    Ptr<Node> routerNode1 = CreateObject<Node> ();
    Ptr<Node> routerNode2 = CreateObject<Node> ();
    NodeContainer serverNodes1, serverNodes2, serverNodes3, serverNodes4, serverNodes5, serverNodes6;
    serverNodes1.Create(6);  // 6 Servers
    serverNodes2.Create(6);  // 6 Servers
    serverNodes3.Create(6);  // 6 Servers
    serverNodes4.Create(6);  // 6 Servers
    serverNodes5.Create(6);  // 6 Servers
    serverNodes6.Create(6);  // 6 Servers

    // Create a CSMA network (Client -> Router -> Servers)
    NodeContainer routerToServers1, routerToServers2, routerToServers3, routerToServers4, routerToServers5, routerToServers6; // , attackerToServer3;
    routerToServers1.Add(routerNode2);
    routerToServers1.Add(serverNodes1);
    routerToServers2.Add(routerNode2);
    routerToServers2.Add(serverNodes2);
    routerToServers3.Add(routerNode2);
    routerToServers3.Add(serverNodes3);
    routerToServers4.Add(routerNode2);
    routerToServers4.Add(serverNodes4);
    routerToServers5.Add(routerNode2);
    routerToServers5.Add(serverNodes5);
    routerToServers6.Add(routerNode2);
    routerToServers6.Add(serverNodes6);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("1.5Mbps"));
    p2p.SetChannelAttribute("Delay", TimeValue(NanoSeconds(20)));

    // Setup CSMA attributes
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("1Gbps"));
    csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(20)));

    // Install CSMA devices on the nodes
    NetDeviceContainer clientRouterDevices = csma.Install(NodeContainer(clientNode, routerNode1));
    NetDeviceContainer router1Router2Devices = p2p.Install(NodeContainer(routerNode1, routerNode2));
    NetDeviceContainer routerServerDevices1 = csma.Install(routerToServers1);
    NetDeviceContainer routerServerDevices2 = csma.Install(routerToServers2);
    NetDeviceContainer routerServerDevices3 = csma.Install(routerToServers3);
    NetDeviceContainer routerServerDevices4 = csma.Install(routerToServers4);
    NetDeviceContainer routerServerDevices5 = csma.Install(routerToServers5);
    NetDeviceContainer routerServerDevices6 = csma.Install(routerToServers6);

    Ptr<NetDevice> rDevice = router1Router2Devices.Get (0);

    // Install Internet stack on all nodes
    InternetStackHelper internet;
    internet.Install(clientNode);
    internet.Install(routerNode1);
    internet.Install(routerNode2);
    // internet.Install(attackerNode);
    internet.Install(serverNodes1);
    internet.Install(serverNodes2);
    internet.Install(serverNodes3);
    internet.Install(serverNodes4);
    internet.Install(serverNodes5);
    internet.Install(serverNodes6);

    if (p4Enabled){
        Ptr<V1ModelP4Queue> customQueue = CreateObject<V1ModelP4Queue> ();
        std::string file = "src/traffic-control/examples/p4-src/detect_selfspec_p2p_2sw/entropy_1sw.txt";
        if(deprioEnabled){
            NS_LOG_INFO ("Deprioritization Enabled.");
            file = "src/traffic-control/examples/p4-src/detect_selfspec_p2p_2sw/entropy_deprio_1sw.txt";
            customQueue->SetAttribute("MaxQueueSize", UintegerValue(10000));
            // customQueue->SetAttribute("MinThreshold", UintegerValue(50));
            // customQueue->SetAttribute("MaxThreshold", UintegerValue(80));
            customQueue->SetAttribute("DeprioritizationEnabled", BooleanValue(true));
        } 
        customQueue->CreateP4Pipe ("src/traffic-control/examples/p4-src/detect_selfspec_p2p_2sw/detect_selfspec_p2p_2sw.json", file);
        Ptr<PointToPointNetDevice> p2pDevice = rDevice->GetObject<PointToPointNetDevice> ();
        p2pDevice->SetQueue(customQueue);
        NS_LOG_INFO ("P4 Enabled.");
    }
    // Assign IP addresses
    // Client and router
    Ipv4AddressHelper address;
    address.SetBase("10.0.0.0", "255.255.255.0");  // Client and Router subnet
    Ipv4InterfaceContainer clientRouterInterfaces = address.Assign(clientRouterDevices);

    address.SetBase("10.1.0.0", "255.255.255.0");  // Client and Router subnet
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
    address.SetBase("10.1.4.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces4 = address.Assign(routerServerDevices4);

    // Router and servers
    address.SetBase("10.1.5.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces5 = address.Assign(routerServerDevices5);

    // Router and servers
    address.SetBase("10.1.6.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces6 = address.Assign(routerServerDevices6);

    Ptr<Ipv4> ipv4Router = routerNode1->GetObject<Ipv4>();
    ipv4Router->SetAttribute("IpForward", BooleanValue(true));

    Ptr<Ipv4> ipv4Router2 = routerNode2->GetObject<Ipv4>();
    ipv4Router2->SetAttribute("IpForward", BooleanValue(true));

    // Start TCP flows
    StartFlows(serverNodes1, clientNode, routerServerInterfaces1);
    StartFlows(serverNodes2, clientNode, routerServerInterfaces2);
    StartFlows(serverNodes3, clientNode, routerServerInterfaces3);
    StartFlows(serverNodes4, clientNode, routerServerInterfaces4);
    StartFlows(serverNodes5, clientNode, routerServerInterfaces5);
    StartFlows(serverNodes6, clientNode, routerServerInterfaces6);

    if(attackEnabled){
        StartVolumetricFlow(serverNodes3, clientNode, routerServerInterfaces3);
        NS_LOG_INFO("Attack Enabled.");
    }
    csma.EnablePcapAll(outPcap+"/packets");  // Trace packets on server side
    p2p.EnablePcapAll(outPcap+"/packets");  // Trace packets on
    NS_LOG_INFO ("PCAP packets will be written in folder: " << outPcap);
    
    // Enable routing globally
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();



    // Run the simulation
    // Simulator::Stop(Seconds(simulationTime));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
