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

NS_LOG_COMPONENT_DEFINE ("VolumetricMultiSpike");


void StartFlows(NodeContainer serverNodes, Ptr<Node> clientNode, Ipv4InterfaceContainer routerServerInterfaces)
{
    // Create TCP flows from client to each server
    
    for (uint32_t i = 0; i < serverNodes.GetN(); ++i)
    {
        uint16_t port = rand() % 32768;
        // Install PacketSink on each server (to act as TCP receiver)
        Address serverAddress(InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), port));
        PacketSinkHelper sinkHelper("ns3::TcpSocketFactory", serverAddress);
        ApplicationContainer serverApp = sinkHelper.Install(serverNodes.Get(i));
        serverApp.Start(Seconds(0.0));

        // Install TCP OnOff client on the client node (to act as TCP sender)
        BulkSendHelper clientHelper("ns3::TcpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), port));

        ApplicationContainer clientApp = clientHelper.Install(clientNode);
        clientApp.Start(Seconds(10.0));  // Start each flow with a slight delay
    }
}

void StartDoS(NodeContainer serverNodes, Ptr<Node> clientNode, Ipv4InterfaceContainer routerServerInterfaces, double start, double finish, uint16_t port, uint16_t addNum)
{
    // Create TCP flows from client to each server
    // uint16_t port = 60000;

    // Address serverAddress(InetSocketAddress(routerServerInterfaces.GetAddress(addNum), port));
    // PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", serverAddress);
    // ApplicationContainer serverApp = sinkHelper.Install(serverNodes.Get(addNum-1));
    // serverApp.Start(Seconds(0.0));
    // serverApp.Stop(Seconds(finish));

    UdpServerHelper server(port);
    ApplicationContainer serverApp = server.Install(serverNodes.Get(addNum-1));
    serverApp.Start(Seconds(0.0)); // Start at 1s
    // serverApp.Stop(Seconds(10.0)); // Stop at 10s


    // Install TCP OnOff client on the client node (to act as TCP sender)
    OnOffHelper clientHelper("ns3::UdpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(addNum), port));
    clientHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    clientHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    clientHelper.SetAttribute("DataRate", DataRateValue(DataRate("40Mbps")));
    // clientHelper.SetAttribute("PacketSize", UintegerValue(1200));  // Packet size

    ApplicationContainer clientApp = clientHelper.Install(clientNode);
    clientApp.Start(Seconds(start));  // Start each flow with a slight delay
    clientApp.Stop(Seconds(finish));
}

void StartLFA(NodeContainer serverNodes, Ptr<Node> clientNode, Ipv4InterfaceContainer routerServerInterfaces)
{
    //TODO: Implement LFA attack
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
    std::system("python3 /home/mininet/ns3-repos/ns-3-allinone/ns-3.29/src/bmv2-tools/controller.py --thrift-port 9091");
    Simulator::Schedule(Seconds(0.1), &UpdateCluster);
}

void DebugStat4(std::string port, std::string log_file){
    std::string cmd = "python3 /home/mininet/ns3-repos/ns-3-allinone/ns-3.29/src/bmv2-tools/debug_stat4.py --thrift-port "+port+" --log-file "+log_file;
    std::system(cmd.c_str());
    Simulator::Schedule(Seconds(0.1), &DebugStat4, port, log_file);
}

void SetupBucketSize(std::string port, std::string bucketSize){
    std::string cmd = "echo \"register_write bucket_size_s 0 \""+bucketSize+" | simple_switch_CLI --thrift-port "+port;
    std::system(cmd.c_str());
}

void SetupPacketsDelay(std::string port, std::string packetsDelay){
    std::string cmd = "echo \"register_write delay_s 0 \""+packetsDelay+" | simple_switch_CLI --thrift-port "+port;
    std::system(cmd.c_str());
}

void ResetDebugStat4File(std::string log_file){
    std::ofstream outputFile(log_file, std::ios::out);
}

void PrintDebugStat4(std::string port, std::string log_file){
    std::string cmd = "echo \"register_read spike_debug_s\" | simple_switch_CLI --thrift-port "+port+" > " + log_file;
    std::system(cmd.c_str());
    cmd = "echo \"register_read d1_debug_s\" | simple_switch_CLI --thrift-port "+port+" >> " + log_file;
    std::system(cmd.c_str());
    cmd = "echo \"register_read d2_debug_s\" | simple_switch_CLI --thrift-port "+port+" >> " + log_file;
    std::system(cmd.c_str());
    cmd = "echo \"register_read fp_s\" | simple_switch_CLI --thrift-port "+port+" >> " + log_file;
    std::system(cmd.c_str());
    // Simulator::Schedule(Seconds(0.1), &DebugStat4, port, log_file);
}

int main(int argc, char *argv[])
{
    Time::SetResolution (Time::NS);
    // Config::SetDefault("ns3::TcpL4Protocol::SocketType", StringValue("ns3::TcpWestwood"));
    std::string outPcap = "trace-data/dos/";
    std::string suffix = "fifo";
    std::string bottleneck = "100Mbps";
    std::string bucketSize = "20";
    std::string packetsDelay = "0";
    bool p4Enabled = false;
    bool deprioEnabled = false;
    bool dropEnabled = false;
    bool accturboEnabled = false;
    bool dosEnabled = false;
    bool lfaEnabled = false;
    
    CommandLine cmd;
    cmd.AddValue ("outPcap", "Simulation PCAP Destination folder", outPcap);
    cmd.AddValue ("p4Enabled", "Enable P4", p4Enabled);
    cmd.AddValue ("deprioEnabled", "Enable Deprioritization, Default FALSE", deprioEnabled);
    cmd.AddValue ("dropEnabled", "Enable Dropping, Default FALSE", dropEnabled);
    cmd.AddValue ("accturboEnabled", "Enable AccTurbo, Default FALSE", accturboEnabled);
    cmd.AddValue ("dosEnabled", "Enable DoS Attack", dosEnabled);
    cmd.AddValue ("lfaEnabled", "Enable Link Flooding Attack", lfaEnabled);
    cmd.AddValue ("bucketSize", "Bucket size (2 ^ bucketSize microseconds buckets)", bucketSize);
    cmd.AddValue ("packetsDelay", "Start drill-down after this number of packets", packetsDelay);
    cmd.Parse (argc, argv);


    LogComponentEnable ("VolumetricMultiSpike", LOG_LEVEL_INFO);
    Packet::EnablePrinting ();
    // Create nodes
    Ptr<Node> clientNode = CreateObject<Node> ();
    Ptr<Node> attackerNode = CreateObject<Node> ();
    Ptr<Node> routerNode1 = CreateObject<Node> ();
    Ptr<Node> routerNode2 = CreateObject<Node> ();
    Ptr<Node> routerNode3 = CreateObject<Node> ();
    Ptr<Node> routerNode4 = CreateObject<Node> ();
    
    NodeContainer serverNodes1, serverNodes2, serverNodes3, serverNodes4, serverNodes5, serverNodes6, serverNodes7, serverNodes8, serverNodesAtk;
    serverNodes1.Create(10);  // 8 Servers
    serverNodes2.Create(10);  // 8 Servers
    serverNodes3.Create(10);  // 8 Servers
    serverNodes4.Create(10);  // 8 Servers
    serverNodes5.Create(10);  // 8 Servers
    serverNodes6.Create(10);  // 8 Servers
    serverNodes7.Create(10);  // 8 Servers
    serverNodes8.Create(10);  // 8 Servers
    serverNodesAtk.Create(10);  // 8 Servers

    // Create a CSMA network (Client -> Router -> Servers)
    NodeContainer routerToServers1, routerToServers2, routerToServers3, routerToServers4, routerToServers5, routerToServers6, routerToServers7, routerToServers8, routerToServersAtk;
    routerToServers1.Add(routerNode4);
    routerToServers1.Add(serverNodes1);
    routerToServers2.Add(routerNode4);
    routerToServers2.Add(serverNodes2);
    routerToServers3.Add(routerNode4);
    routerToServers3.Add(serverNodes3);
    routerToServers4.Add(routerNode4);
    routerToServers4.Add(serverNodes4);
    routerToServers5.Add(routerNode4);
    routerToServers5.Add(serverNodes5);
    routerToServers6.Add(routerNode4);
    routerToServers6.Add(serverNodes6);
    routerToServers7.Add(routerNode4);
    routerToServers7.Add(serverNodes7);
    routerToServers8.Add(routerNode4);
    routerToServers8.Add(serverNodes8);
    routerToServersAtk.Add(routerNode4);
    routerToServersAtk.Add(serverNodesAtk);


    PointToPointHelper p2pc;
    p2pc.SetDeviceAttribute("DataRate", StringValue("4Mbps"));
    p2pc.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue(bottleneck));
    p2p.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    PointToPointHelper p2pa;
    p2pa.SetDeviceAttribute("DataRate", StringValue("40Mbps"));
    p2pa.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    PointToPointHelper p2p2;
    p2p2.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p2.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    // Setup CSMA attributes
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("10Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    // Install CSMA devices on the nodes
    NetDeviceContainer clientRouterDevices = p2pc.Install(NodeContainer(clientNode, routerNode1));
    NetDeviceContainer attackerRouterDevices = p2pa.Install(NodeContainer(attackerNode, routerNode1));
    NetDeviceContainer router1Router2Devices = p2p.Install(NodeContainer(routerNode1, routerNode2));
    NetDeviceContainer router2Router3Devices = p2p2.Install(NodeContainer(routerNode2, routerNode3));
    NetDeviceContainer router3Router4Devices = p2p2.Install(NodeContainer(routerNode3, routerNode4));
    NetDeviceContainer routerServerDevices1 = csma.Install(routerToServers1);
    NetDeviceContainer routerServerDevices2 = csma.Install(routerToServers2);
    NetDeviceContainer routerServerDevices3 = csma.Install(routerToServers3);
    NetDeviceContainer routerServerDevices4 = csma.Install(routerToServers4);
    NetDeviceContainer routerServerDevices5 = csma.Install(routerToServers5);
    NetDeviceContainer routerServerDevices6 = csma.Install(routerToServers6);
    NetDeviceContainer routerServerDevices7 = csma.Install(routerToServers7);
    NetDeviceContainer routerServerDevices8 = csma.Install(routerToServers8);
    NetDeviceContainer routerServerDevicesAtk = csma.Install(routerToServersAtk);

    Ptr<NetDevice> r1Device = router1Router2Devices.Get (0);
    Ptr<NetDevice> r2Device = router2Router3Devices.Get (0);

    // Set up a queue with a maximum of 10 packets
    if (p4Enabled == false){
        Ptr<PointToPointNetDevice> device = DynamicCast<PointToPointNetDevice>(r2Device);
        Ptr<Queue<Packet>> queue = device->GetQueue();
        queue->SetAttribute("MaxSize", QueueSizeValue(QueueSize(QueueSizeUnit::PACKETS, 1)));
    }

    // Install Internet stack on all nodes
    InternetStackHelper internet;
    internet.Install(clientNode);
    internet.Install(attackerNode);
    internet.Install(routerNode1);
    internet.Install(routerNode2);
    internet.Install(routerNode3);
    internet.Install(routerNode4);
    internet.Install(serverNodes1);
    internet.Install(serverNodes2);
    internet.Install(serverNodes3);
    internet.Install(serverNodes4);
    internet.Install(serverNodes5);
    internet.Install(serverNodes6);
    internet.Install(serverNodes7);
    internet.Install(serverNodes8);
    internet.Install(serverNodesAtk);


    NS_LOG_INFO ("Configure Tracing."); //Dummy P4 switch for reproducibility
    Ptr<V1ModelP4Queue> customQueue = CreateObject<V1ModelP4Queue> ();
    customQueue->CreateP4Pipe ("src/traffic-control/examples/p4-src/stat4_pwd/stat4_pwd.json", "src/traffic-control/examples/p4-src/stat4_pwd/anomaly.txt");
    customQueue->SetOutPath(outPcap+"stat4debug9090.txt");
    Ptr<PointToPointNetDevice> p2pDevice = r1Device->GetObject<PointToPointNetDevice> ();
    // Simulator::Schedule(Seconds(0), &DebugStat4, "9090", outPcap+"/stat4debug9090.log");
    Simulator::Schedule(Seconds(0), &SetupBucketSize, "9090", bucketSize);
    // customQueue->SetAttribute("MaxQueueSize", UintegerValue(100));
    p2pDevice->SetQueue(customQueue);
    if (p4Enabled){
        if (accturboEnabled == false){            
      
            Ptr<V1ModelP4Queue> customQueue2 = CreateObject<V1ModelP4Queue> ();
            std::string p4file = "src/traffic-control/examples/p4-src/stat4_pwd/stat4_pwd.json";
            std::string file = "src/traffic-control/examples/p4-src/stat4_pwd/anomaly.txt";
            customQueue2->SetAttribute("MaxQueueSize", UintegerValue(1));
            if(deprioEnabled){
                NS_LOG_INFO ("Deprioritization Enabled.");
                file = "src/traffic-control/examples/p4-src/stat4_pwd/entropy_deprio_subhash.txt";
                customQueue2->SetAttribute("DeprioritizationEnabled", BooleanValue(true));
                suffix = "stat4-deprio";
            } 
            if (dropEnabled){
                NS_LOG_INFO ("Dropping Enabled.");
                file = "src/traffic-control/examples/p4-src/stat4_pwd/entropy_drop_subhash.txt";
                suffix = "stat4-drop";
            }   
            customQueue2->CreateP4Pipe (p4file, file);
            customQueue2->SetOutPath(outPcap+"stat4debug9091.txt");
            Ptr<PointToPointNetDevice> p2pDevice2 = r2Device->GetObject<PointToPointNetDevice> ();
            // Simulator::Schedule(Seconds(0), &DebugStat4, "9091", outPcap+"/stat4debug9091.log");
            Simulator::Schedule(Seconds(0), &SetupBucketSize, "9091", bucketSize);
            if(packetsDelay != "0"){
                // NS_LOG_INFO ("Packets Delay Enabled."+packetsDelay);
                Simulator::Schedule(Seconds(0), &SetupPacketsDelay, "9091", packetsDelay);
            }
            p2pDevice2->SetQueue(customQueue2);
        } else {
            NS_LOG_INFO ("Accturbo Enabled.");
            Ptr<V1ModelP4Queue> customQueue = CreateObject<V1ModelP4Queue> ();
            std::string p4file = "src/traffic-control/examples/p4-src/accturbo/accturbo.json";
            std::string file = "src/traffic-control/examples/p4-src/accturbo/setup_prio.txt";

            Ptr<PointToPointNetDevice> p2pDevice = r2Device->GetObject<PointToPointNetDevice> ();

            customQueue->CreateP4Pipe (p4file, file);
            customQueue->SetAttribute("MaxQueueSize", UintegerValue(1));
            customQueue->SetAttribute("DeprioritizationEnabled", BooleanValue(true));
            customQueue->SetOutPath(outPcap+"second_sw.txt");
            Simulator::Schedule(Seconds(0), &UpdateCluster);
            p2pDevice->SetQueue(customQueue);
            suffix = "accturbo";
        }
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

    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer router2Router3Interfaces = address.Assign(router2Router3Devices);

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer router3Router4Interfaces = address.Assign(router3Router4Devices);
    
    // Router and servers
    address.SetBase("10.1.3.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces1 = address.Assign(routerServerDevices1);

    // Router and servers
    address.SetBase("10.1.4.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces2 = address.Assign(routerServerDevices2);

    // Router and servers
    address.SetBase("10.1.5.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces3 = address.Assign(routerServerDevices3);

    // Router and servers
    address.SetBase("10.1.6.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces4 = address.Assign(routerServerDevices4);

    // Router and servers
    address.SetBase("10.1.7.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces5 = address.Assign(routerServerDevices5);

    // Router and servers
    address.SetBase("10.1.8.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces6 = address.Assign(routerServerDevices6);

        // Router and servers
    address.SetBase("10.1.9.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces7 = address.Assign(routerServerDevices7);

        // Router and servers
    address.SetBase("10.1.10.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfaces8 = address.Assign(routerServerDevices8);

    // // Router and servers
    address.SetBase("192.168.0.0", "255.255.255.0");  // Router and Server subnet
    Ipv4InterfaceContainer routerServerInterfacesAtk = address.Assign(routerServerDevicesAtk);

    Ptr<Ipv4> ipv4Router = routerNode1->GetObject<Ipv4>();
    ipv4Router->SetAttribute("IpForward", BooleanValue(true));

    Ptr<Ipv4> ipv4Router2 = routerNode2->GetObject<Ipv4>();
    ipv4Router2->SetAttribute("IpForward", BooleanValue(true));

    Ptr<Ipv4> ipv4Router3 = routerNode3->GetObject<Ipv4>();
    ipv4Router3->SetAttribute("IpForward", BooleanValue(true));

    Ptr<Ipv4> ipv4Router4 = routerNode4->GetObject<Ipv4>();
    ipv4Router4->SetAttribute("IpForward", BooleanValue(true));

    // Start TCP flows
    StartFlows(serverNodes1, clientNode, routerServerInterfaces1);
    StartFlows(serverNodes2, clientNode, routerServerInterfaces2);
    StartFlows(serverNodes3, clientNode, routerServerInterfaces3);
    StartFlows(serverNodes4, clientNode, routerServerInterfaces4);
    StartFlows(serverNodes5, clientNode, routerServerInterfaces5);
    StartFlows(serverNodes6, clientNode, routerServerInterfaces6);
    StartFlows(serverNodes7, clientNode, routerServerInterfaces7);
    StartFlows(serverNodes8, clientNode, routerServerInterfaces8);
    StartFlows(serverNodesAtk, clientNode, routerServerInterfacesAtk);

    if(dosEnabled){
        // StartDoS(serverNodes1, attackerNode, routerServerInterfaces1, 20, 35, 50000); //to keep same IP for analysis
        // StartDoS(serverNodes1, attackerNode, routerServerInterfaces1, 55, 70, 60000); //to keep same IP for analysis
        StartDoS(serverNodesAtk, attackerNode, routerServerInterfacesAtk, 30.0, 40.0, 40000, 2); //to keep same IP for analysis
        StartDoS(serverNodesAtk, attackerNode, routerServerInterfacesAtk, 60.0, 70.0, 49000, 2); //to keep same IP for analysis
        StartDoS(serverNodesAtk, attackerNode, routerServerInterfacesAtk, 90.0, 100.0, 44000, 2); //to keep same IP for analysis
        StartDoS(serverNodesAtk, attackerNode, routerServerInterfacesAtk, 120.0, 130.0, 46000, 2); //to keep same IP for analysis

        // StartDoS(serverNodes1, attackerNode, routerServerInterfaces1, 30.0, 40.0, 40000, 2); //to keep same IP for analysis
        // StartDoS(serverNodes1, attackerNode, routerServerInterfaces1, 60.0, 70.0, 49000, 2); //to keep same IP for analysis
        // StartDoS(serverNodes1, attackerNode, routerServerInterfaces1, 90.0, 100.0, 44000, 2); //to keep same IP for analysis
        // StartDoS(serverNodes1, attackerNode, routerServerInterfaces1, 120.0, 130.0, 46000, 2); //to keep same IP for analysis

        NS_LOG_INFO("DoS Attack Enabled.");
    }
    if(lfaEnabled){
        StartLFA(serverNodes1, attackerNode, routerServerInterfaces1); //TODO: Not implemented yet
        NS_LOG_INFO("Link Flooding Attack Enabled.");
    }

    // csma.EnablePcapAll(outPcap+"/packets");  // Trace packets on server side
    p2p2.EnablePcap(outPcap+suffix, router3Router4Devices.Get(1), true);
    NS_LOG_INFO ("PCAP packets will be written in folder: " << outPcap);
    
    // Enable routing globally
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    Simulator::Schedule(Seconds(0), &ResetDebugStat4File, outPcap+"stat4debug9090.log");
    Simulator::Schedule(Seconds(0), &ResetDebugStat4File, outPcap+"stat4debug9091.log");
    Simulator::Schedule(Seconds(130), &PrintDebugStat4, "9090", outPcap+"stat4debug9090.log");
    Simulator::Schedule(Seconds(130), &PrintDebugStat4, "9091", outPcap+"stat4debug9091.log");


    // Run the simulation
    Simulator::Stop(Seconds(140));
    Simulator::Run();

    Simulator::Destroy();

    return 0;
}
