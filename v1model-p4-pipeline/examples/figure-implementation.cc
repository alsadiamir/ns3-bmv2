#include <iostream>
#include <fstream>
#include <set> // Include header for std::set

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
#include "ns3/mpi-interface.h"


using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("VolumetricMultiSpike");

// Shared set to track used ports
std::set<uint16_t> usedPorts;

static std::map<uint32_t, uint32_t> interfacePacketCount; // Map to store packets per interface

// Callback function to count packets per interface
void RouterPacketReceivedCallback(Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface) {
    interfacePacketCount[interface]++;  // Increment count for this interface
    // if(interface == 1) {
    //     std::cout << "Packet received on interface " << interface << " with size " << packet->GetSize() << std::endl;
    // }

}

// Function to print & log received packets per interface per second
void PrintRouterReceivedPacketRate(std::string path) {
    std::ofstream outFile(path+"-router_interface_log.txt", std::ios::app); // Open log file in append mode

    if (outFile.is_open()) {
        outFile << "[Time: " << Simulator::Now().GetSeconds() << "s] Packets received per interface:\n";
        std::cout << "[Time: " << Simulator::Now().GetSeconds() << "s] Packets received per interface:\n";
        
        for (auto &entry : interfacePacketCount) {
            uint32_t interface = entry.first;
            uint32_t count = entry.second;
            outFile << "  Interface " << interface << ": " << count << " packets/sec\n";
            std::cout << "  Interface " << interface << ": " << count << " packets/sec\n";
            entry.second = 0; // Reset count after logging
        }

        outFile << "----------------------------\n";
        outFile.close();
    } else {
        std::cerr << "Error: Could not open log file!" << std::endl;
    }

    // Schedule the next logging event
    Simulator::Schedule(Seconds(1.0), &PrintRouterReceivedPacketRate, path);
}

// Attach the callback to all interfaces of the router
void AttachRouterPacketCounter(Ptr<Node> routerNode, std::string path) {
    Ptr<Ipv4> ipv4 = routerNode->GetObject<Ipv4>();

    for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++) {
        ipv4->TraceConnectWithoutContext("Rx", MakeCallback(&RouterPacketReceivedCallback));
    }

    // Start periodic logging
    Simulator::Schedule(Seconds(1.0), &PrintRouterReceivedPacketRate, path);
}


static uint32_t packetsSent = 0;  // Variable to store the count of packets sent

// Callback function to count the number of packets sent by the TCP client
void TcpClientPacketSent(Ptr<const Packet> packet) {
    packetsSent++; // Increment the packet count when a packet is sent
}

// Periodic function to log the packets sent by the TCP client per second
void LogPacketsSent() {
    std::ofstream outFile("trace-data/implementation/x2/tcp_client_packets_sent.txt", std::ios::app); // Open the log file in append mode
    if (outFile.is_open()) {
        outFile << "[Time: " << Simulator::Now().GetSeconds() << "s] Packets sent: " << packetsSent << " packets/sec\n";
        std::cout << "[Time: " << Simulator::Now().GetSeconds() << "s] Packets sent: " << packetsSent << " packets/sec\n";
        
        packetsSent = 0;  // Reset the packet count after logging
        outFile.close();
    } else {
        std::cerr << "Error: Could not open log file!" << std::endl;
    }

    // Schedule the next log
    Simulator::Schedule(Seconds(1.0), &LogPacketsSent);
}

// Function to log the packet size being transmitted
void LogPacketSize(Ptr<const Packet> packet, Ptr<NetDevice> device)
{
    std::cout << "Packet sent with size: " << packet->GetSize() 
              << " bytes from interface: " << device->GetIfIndex() << std::endl;
}

void StartFlows(NodeContainer serverNodes, Ptr<Node> clientNode, Ipv4InterfaceContainer routerServerInterfaces)
{
    for (uint32_t i = 0; i < serverNodes.GetN(); ++i)
    {
        uint16_t port = rand() % 32768;
        // Install PacketSink on each server (TCP receiver)
        Address serverAddress(InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), port));
        PacketSinkHelper sinkHelper("ns3::TcpSocketFactory", serverAddress);
        ApplicationContainer serverApp = sinkHelper.Install(serverNodes.Get(i));
        
        serverApp.Start(Seconds(0.0));

        // Install TCP BulkSend client (TCP sender)
        BulkSendHelper clientHelper("ns3::TcpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), port));
        // clientHelper.SetAttribute("PacketSize", UintegerValue(1500));
        // clientHelper.SetAttribute("MaxBytes", UintegerValue(0));  // Unrestricted size (optional)
        // clientHelper.SetAttribute("SendSize", UintegerValue(1460));  // by default, 512

        ApplicationContainer clientApp = clientHelper.Install(clientNode);
        clientApp.Start(Seconds(10.0));

        // Attach a callback to count packets sent by the TCP client
        // if (i == 0) {
        //     // Attach a trace callback to count packets sent
        //     Ptr<Application> app = clientApp.Get(0);
        //     Ptr<BulkSendApplication> bulkSendApp = DynamicCast<BulkSendApplication>(app);

        //     if (bulkSendApp) {
        //         // Attach a callback to count packets sent by the TCP client
        //         Ptr<Socket> socket = bulkSendApp->GetSocket();
        //         socket->TraceConnectWithoutContext("Tx", MakeCallback(&TcpClientPacketSent));
        //     }

        //     // Start periodic logging to track packets sent per second
        //     Simulator::Schedule(Seconds(1.0), &LogPacketsSent);
        // }
    }
}

void StartDoS(NodeContainer serverNodes, Ptr<Node> clientNode, Ipv4InterfaceContainer routerServerInterfaces, double start, double finish, uint16_t port, uint16_t addNum, std::string datarate)
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
    serverApp.Start(Seconds(start)); // Start at 1s
    serverApp.Stop(Seconds(finish)); // Stop at 10s


    // Install TCP OnOff client on the client node (to act as TCP sender)
    OnOffHelper clientHelper("ns3::UdpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(addNum), port));
    clientHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    clientHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    clientHelper.SetAttribute("DataRate", DataRateValue(DataRate(datarate)));
    clientHelper.SetAttribute("PacketSize", UintegerValue(1500));  // Packet size
    // clientHelper.SetAttribute("PacketSize", UintegerValue(1200));  // Packet size

    ApplicationContainer clientApp = clientHelper.Install(clientNode);
    clientApp.Start(Seconds(start));  // Start each flow with a slight delay
    clientApp.Stop(Seconds(finish));
}

void StartDoSUdpClient(NodeContainer serverNodes, Ptr<Node> clientNode, 
    Ipv4InterfaceContainer routerServerInterfaces, double start, double finish, 
    uint16_t port, uint16_t addNum, std::string datarate) 
{
    // Install UDP Server on the target server node
    UdpServerHelper server(port);
    ApplicationContainer serverApp = server.Install(serverNodes.Get(addNum - 1));
    serverApp.Start(Seconds(start));
    serverApp.Stop(Seconds(finish));

    // Convert DataRate to packet interval
    DataRate dataRateObj(datarate);
    uint32_t packetSize = 1500;  // Packet size in bytes
    double interval = (packetSize * 8.0) / dataRateObj.GetBitRate(); // Time between packets in seconds
    std::cout << "Interval: " << interval << std::endl;

    // Install UDP Client on the attacking node
    UdpClientHelper client(InetSocketAddress(routerServerInterfaces.GetAddress(addNum), port));
    client.SetAttribute("MaxPackets", UintegerValue(4294967295)); // Essentially unlimited packets
    client.SetAttribute("Interval", TimeValue(Seconds(interval))); // Packet sending interval
    client.SetAttribute("PacketSize", UintegerValue(packetSize-28)); // Packet size

    ApplicationContainer clientApp = client.Install(clientNode);
    clientApp.Start(Seconds(start));
    clientApp.Stop(Seconds(finish));
}

void StartCoremeltAttack(NodeContainer serverNodes, NodeContainer clientNodes, 
                         Ipv4InterfaceContainer routerServerInterfaces, 
                         double start, double finish, int startPort, std::string datarate)
{
    uint32_t numFlows = serverNodes.GetN() * clientNodes.GetN(); // Total number of flows

    if (numFlows == 0) {
        NS_LOG_WARN("No flows created as either serverNodes or clientNodes is empty.");
        return;
    }
    // numFlows = 10;

    // Convert total data rate string (e.g., "100Mbps") to ns3::DataRate and divide
    DataRate totalDataRate(datarate);
    uint64_t perFlowRateBps = totalDataRate.GetBitRate() / numFlows;  // Data rate per flow in bits per second
    std::string perFlowRateStr = std::to_string(perFlowRateBps) + "bps"; // Convert back to string

    // Create flows from each client to each server
    // for (uint32_t i = 0; i < serverNodes.GetN(); ++i)
    // {
    uint16_t i = 0;
        for (uint32_t j = 0; j < clientNodes.GetN(); ++j)
        {
            for (uint16_t port = startPort; port < startPort+10; ++port)
            {
                uint16_t p = startPort + 1000 * (i + j);

                // Ensure the port is unique
                while (usedPorts.find(p) != usedPorts.end()) {
                    ++p;
                }
                usedPorts.insert(p);

                // Install PacketSink on the server (receiver)
                Address serverAddress(InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), p));
                PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", serverAddress);
                ApplicationContainer serverApp = sinkHelper.Install(serverNodes.Get(i));
                serverApp.Start(Seconds(start));
                serverApp.Stop(Seconds(finish));

                // Install OnOff client on the client node (sender)
                OnOffHelper clientHelper("ns3::UdpSocketFactory", InetSocketAddress(routerServerInterfaces.GetAddress(i + 1), p));
                // clientHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
                // clientHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
                clientHelper.SetAttribute("DataRate", DataRateValue(DataRate(datarate))); // Adjusted rate per flow
                clientHelper.SetAttribute("PacketSize", UintegerValue(1500));
                // clientHelper.SetAttribute("StopTime", TimeValue(Seconds(finish)));


                ApplicationContainer clientApp = clientHelper.Install(clientNodes.Get(j));
                clientApp.Start(Seconds(start));
                clientApp.Stop(Seconds(finish));
            }
        }
    // }
}

void StartUdpFlows(NodeContainer serverNodes, NodeContainer clientNodes, 
    Ipv4InterfaceContainer routerServerInterfaces, 
    double start, double finish, int startPort, std::string datarate) 
{
    int numFlows = 100;
    Ptr<UniformRandomVariable> random = CreateObject<UniformRandomVariable>();
    DataRate totalDataRate(datarate);
    uint64_t perAtkRateBps = totalDataRate.GetBitRate() / numFlows;  // Data rate per flow in bits per second
    std::string perAtkRateStr = std::to_string(perAtkRateBps) + "bps"; // Convert back to string

    for (int i = 0; i < numFlows; ++i) {
        // Select random server and client nodes
        uint32_t serverIndex = random->GetInteger(0, serverNodes.GetN() - 1);
        uint32_t clientIndex;

        do {
            clientIndex = random->GetInteger(0, clientNodes.GetN() - 1);
        } while (serverIndex == clientIndex); // Ensure client and server are different

        Ptr<Node> serverNode = serverNodes.Get(serverIndex);
        Ptr<Node> clientNode = clientNodes.Get(clientIndex);

        Ipv4Address serverIp = routerServerInterfaces.GetAddress(serverIndex);
        uint16_t port = startPort + i; // Increment port for each flow

        // Create a UDP sink on the server
        PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), port));
        ApplicationContainer sinkApp = sinkHelper.Install(serverNode);
        sinkApp.Start(Seconds(start));
        sinkApp.Stop(Seconds(finish));
    
        // Convert DataRate to packet interval
        DataRate dataRateObj(datarate);
        uint32_t packetSize = 1500;  // Packet size in bytes
        double interval = (packetSize * 8.0) / dataRateObj.GetBitRate(); // Time between packets in seconds
        std::cout << "Interval: " << interval << std::endl;
    
        // Install UDP Client on the attacking node
        UdpClientHelper client(InetSocketAddress(serverIp, port));
        client.SetAttribute("MaxPackets", UintegerValue(4294967295)); // Essentially unlimited packets
        client.SetAttribute("Interval", TimeValue(Seconds(interval))); // Packet sending interval
        client.SetAttribute("PacketSize", UintegerValue(packetSize-28)); // Packet size
    
        ApplicationContainer clientApp = client.Install(clientNode);
        clientApp.Start(Seconds(start));
        clientApp.Stop(Seconds(finish));
    }
}

void StartRandomUdpFlow(NodeContainer clientNodes, NodeContainer serverNodes, 
    double startTime, double stopTime, std::string dataRate) {
    // Create random variable generator
    Ptr<UniformRandomVariable> random = CreateObject<UniformRandomVariable>();

    // Randomly select source and destination nodes
    uint32_t srcIndex = random->GetInteger(0, clientNodes.GetN() - 1);  // Source from clientNodes
    uint32_t dstIndex = random->GetInteger(0, serverNodes.GetN() - 1);  // Destination from serverNodes

    Ptr<Node> srcNode = clientNodes.Get(srcIndex);
    Ptr<Node> dstNode = serverNodes.Get(dstIndex);

    // Generate a random port number between 4000 and 6000
    uint16_t port = random->GetInteger(4000, 6000);

    // Get the IP address of the destination node (server node)
    Ipv4Address dstIp = dstNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();  // Assuming interface 1

    // Create a UDP sink on the destination node (server node) to receive the data
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer sinkApp = sinkHelper.Install(dstNode);
    sinkApp.Start(Seconds(startTime));
    sinkApp.Stop(Seconds(stopTime));

    // Create OnOff application on the source node (client node) to send data to the destination
    OnOffHelper onoff("ns3::UdpSocketFactory", InetSocketAddress(dstIp, port));
    onoff.SetAttribute("DataRate", StringValue(dataRate));  // Set the data rate
    onoff.SetAttribute("PacketSize", UintegerValue(1024));  // Set packet size
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer sourceApp = onoff.Install(srcNode);
    sourceApp.Start(Seconds(startTime));  // Start the flow at startTime
    sourceApp.Stop(Seconds(stopTime));  // Stop the flow at stopTime

    // Log the chosen source, destination, and port for debugging
    // NS_LOG_UNCOND("UDP Flow: " << srcNode->GetId() << " -> " 
    //         << dstNode->GetId() << " on port " << port);
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

void LogPacketsStat4(std::string port, std::string log_file){
    std::string cmd = "echo \"************************************************************ Simulation Time: " 
                  + std::to_string(ns3::Simulator::Now().GetSeconds()) 
                  + "s\" >> " + log_file;
    std::system(cmd.c_str());
    cmd = "python3 /home/mininet/ns3-repos/ns-3-allinone/ns-3.29/src/bmv2-tools/log_tcp_udp.py --thrift-port "+port+" --log-file "+log_file;
    std::system(cmd.c_str());
    Simulator::Schedule(Seconds(1), &LogPacketsStat4, port, log_file);
}

void SetupBucketSize(std::string port, std::string bucketSize){
    std::string cmd = "echo \"register_write bucket_size_s 0 \""+bucketSize+" | simple_switch_CLI --thrift-port "+port;
    std::system(cmd.c_str());
}

void SetupPacketsDelay(std::string port, std::string packetsDelay){
    std::string cmd = "echo \"register_write delay_s 0 \""+packetsDelay+" | simple_switch_CLI --thrift-port "+port;
    std::system(cmd.c_str());
}

void SetupAttackType(std::string port, std::string attacktype){
    std::string cmd = "echo \"register_write type_attack_s 0 \""+attacktype+" | simple_switch_CLI --thrift-port "+port;
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
    // ns3::MpiInterface::Enable(&argc, &argv);
    Time::SetResolution (Time::NS);
    // Config::SetDefault("ns3::TcpL4Protocol::SocketType", StringValue("ns3::TcpWestwood"));
    std::string outPcap = "trace-data/dos/";
    std::string suffix = "fifo";
    std::string atk_suffix = "fifo";
    std::string bottleneck = "200Mbps";
    std::string bucketSize = "20";
    std::string packetsDelay = "0";
    std::string datarate = "80Mbps";
    bool p4Enabled = false;
    bool deprioEnabled = false;
    bool dropEnabled = false;
    bool accturboEnabled = false;
    bool dosEnabled = false;
    bool lfaEnabled = false;

    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue (1448));
    // Disabling Nagle's algorithm for all TCP sockets
    // Config::Set("/NodeList/*/DeviceList/*/Queue/DropTailQueue/MaxSize", StringValue("1000p"));
    // Config::Set("/NodeList/*/DeviceList/*/Socket/TCP_NODELAY", BooleanValue(true));
    
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
    cmd.AddValue ("datarate", "Attack datarate", datarate);
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
    
    NodeContainer clientLfaNodes, serverNodes1, serverNodes2, serverNodes3, serverNodes4, serverNodes5, serverNodes6, serverNodes7, serverNodes8, serverNodesAtk;
    clientLfaNodes.Create(10);
    // clientNodes.Add(clientNode);
    serverNodes1.Create(10);  // 8 Servers
    serverNodes2.Create(10);  // 8 Servers
    serverNodes3.Create(10);  // 8 Servers
    serverNodes4.Create(10);  // 8 Servers
    serverNodes5.Create(10);  // 8 Servers
    serverNodes6.Create(10);  // 8 Servers
    serverNodes7.Create(10);  // 8 Servers
    serverNodes8.Create(10);  // 8 Servers
    serverNodesAtk.Create(10);  // 8 Servers

    // Ptr<Node> clientNode = clientNodes.Get(0);

    // Create a CSMA network (Client -> Router -> Servers)
    NodeContainer routerToServers1, routerToServers2, routerToServers3, routerToServers4, routerToServers5, routerToServers6, routerToServers7, routerToServers8, routerToServersAtk, clientLfaToRouter;
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
    clientLfaToRouter.Add(clientLfaNodes);
    clientLfaToRouter.Add(routerNode1);


    PointToPointHelper p2pc;
    p2pc.SetDeviceAttribute("DataRate", StringValue("4Mbps"));
    p2pc.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue(bottleneck));
    p2p.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    PointToPointHelper p2pa;
    p2pa.SetDeviceAttribute("DataRate", StringValue(datarate));
    p2pa.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    PointToPointHelper p2p2;
    p2p2.SetDeviceAttribute("DataRate", StringValue(bottleneck));
    p2p2.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    // Setup CSMA attributes
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("4Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    CsmaHelper csmalfa;
    csmalfa.SetChannelAttribute("DataRate", StringValue(datarate));
    csmalfa.SetChannelAttribute("Delay", TimeValue(MicroSeconds(50)));

    // Install CSMA devices on the nodes
    NetDeviceContainer clientRouterDevices = p2pc.Install(NodeContainer(clientNode, routerNode1));

    //fix here the client lfa wiring
    NetDeviceContainer clientLfaRouterDevices = csmalfa.Install(clientLfaToRouter);
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

    for (uint32_t i = 0; i < clientRouterDevices.GetN(); ++i)
    {
        Ptr<NetDevice> device = clientRouterDevices.Get(i);
        device->SetMtu(1500);  // Set MTU to 1500 bytes (common for Ethernet)
    }

    for (uint32_t i = 0; i < routerServerDevices1.GetN(); ++i)
    {
        Ptr<NetDevice> device = routerServerDevices1.Get(i);
        device->SetMtu(1500);  // Set MTU to 1500 bytes (common for Ethernet)
    }

    for (uint32_t i = 0; i < routerServerDevices2.GetN(); ++i)
    {
        Ptr<NetDevice> device = routerServerDevices2.Get(i);
        device->SetMtu(1500);  // Set MTU to 1500 bytes (common for Ethernet)
    }

    for (uint32_t i = 0; i < routerServerDevices3.GetN(); ++i)
    {
        Ptr<NetDevice> device = routerServerDevices3.Get(i);
        device->SetMtu(1500);  // Set MTU to 1500 bytes (common for Ethernet)
    }

    for (uint32_t i = 0; i < routerServerDevices4.GetN(); ++i)
    {
        Ptr<NetDevice> device = routerServerDevices4.Get(i);
        device->SetMtu(1500);  // Set MTU to 1500 bytes (common for Ethernet)
    }

    for (uint32_t i = 0; i < routerServerDevices5.GetN(); ++i)
    {
        Ptr<NetDevice> device = routerServerDevices5.Get(i);
        device->SetMtu(1500);  // Set MTU to 1500 bytes (common for Ethernet)
    }

    for (uint32_t i = 0; i < routerServerDevices6.GetN(); ++i)
    {
        Ptr<NetDevice> device = routerServerDevices6.Get(i);
        device->SetMtu(1500);  // Set MTU to 1500 bytes (common for Ethernet)
    }

    for (uint32_t i = 0; i < routerServerDevices7.GetN(); ++i)
    {
        Ptr<NetDevice> device = routerServerDevices7.Get(i);
        device->SetMtu(1500);  // Set MTU to 1500 bytes (common for Ethernet)
    }   

    for (uint32_t i = 0; i < routerServerDevices8.GetN(); ++i)
    {
        Ptr<NetDevice> device = routerServerDevices8.Get(i);
        device->SetMtu(1500);  // Set MTU to 1500 bytes (common for Ethernet)
    }

    for (uint32_t i = 0; i < routerServerDevicesAtk.GetN(); ++i)
    {
        Ptr<NetDevice> device = routerServerDevicesAtk.Get(i);
        device->SetMtu(1500);  // Set MTU to 1500 bytes (common for Ethernet)
    }



    Ptr<NetDevice> r1Device = router1Router2Devices.Get (0);
    Ptr<NetDevice> r2Device = router2Router3Devices.Get (0);

    csmalfa.SetQueue("ns3::DropTailQueue", "MaxSize", StringValue("1p"));
    p2pa.SetQueue("ns3::DropTailQueue", "MaxSize", StringValue("1p"));
    p2pc.SetQueue("ns3::DropTailQueue", "MaxSize", StringValue("1p"));
    p2p.SetQueue("ns3::DropTailQueue", "MaxSize", StringValue("1p"));
    csma.SetQueue("ns3::DropTailQueue", "MaxSize", StringValue("1p"));

    // Set up a queue with a maximum of 10 packets
    if (p4Enabled == false){
        Ptr<PointToPointNetDevice> device = DynamicCast<PointToPointNetDevice>(r2Device);
        Ptr<Queue<Packet>> queue = device->GetQueue();
        queue->SetAttribute("MaxSize", QueueSizeValue(QueueSize(QueueSizeUnit::PACKETS, 1)));
    }

    if(lfaEnabled == true){
        atk_suffix = "lfa";
    } else if (dosEnabled == true){
        atk_suffix = "dos";
    }

    // Install Internet stack on all nodes
    InternetStackHelper internet;
    internet.Install(clientLfaNodes);
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
    customQueue->CreateP4Pipe ("src/traffic-control/examples/p4-src/stat4_ds/stat4_ds.json", "src/traffic-control/examples/p4-src/stat4_ds/anomaly.txt");
    customQueue->SetOutPath(outPcap+atk_suffix+"-stat4debug9090.txt");
    Ptr<PointToPointNetDevice> p2pDevice = r1Device->GetObject<PointToPointNetDevice> ();
    Simulator::Schedule(Seconds(30), &LogPacketsStat4, "9090", outPcap+atk_suffix+"-stat4debug9090.log");
    Simulator::Schedule(Seconds(0), &SetupBucketSize, "9090", bucketSize);
    customQueue->SetAttribute("MaxQueueSize", UintegerValue(1));
    p2pDevice->SetQueue(customQueue);
    if (p4Enabled){
        if (accturboEnabled == false){            
      
            Ptr<V1ModelP4Queue> customQueue2 = CreateObject<V1ModelP4Queue> ();
            std::string p4file = "src/traffic-control/examples/p4-src/stat4_ds/stat4_ds.json";
            std::string file = "src/traffic-control/examples/p4-src/stat4_ds/anomaly.txt";
            customQueue2->SetAttribute("MaxQueueSize", UintegerValue(1));
            if(deprioEnabled){
                NS_LOG_INFO ("Deprioritization Enabled.");
                file = "src/traffic-control/examples/p4-src/stat4_ds/entropy_deprio_subhash.txt";
                customQueue2->SetAttribute("DeprioritizationEnabled", BooleanValue(true));
                suffix = "stat4-deprio";
            } 
            if (dropEnabled){
                NS_LOG_INFO ("Dropping Enabled.");
                file = "src/traffic-control/examples/p4-src/stat4_ds/entropy_drop_subhash.txt";
                suffix = "stat4-drop";
            }   
            customQueue2->CreateP4Pipe (p4file, file);
            customQueue2->SetOutPath(outPcap+atk_suffix+"-stat4debug9091.txt");
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
            customQueue->SetOutPath(outPcap+atk_suffix+"-second_sw.txt");
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

    address.SetBase("10.0.1.0", "255.255.255.0");  // Client and Router subnet
    Ipv4InterfaceContainer clientLfaRouterInterfaces = address.Assign(clientLfaRouterDevices);

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
    // AttachRouterPacketCounter(routerNode1, outPcap+atk_suffix);
    // AttachRouterPacketCounter(routerNode4);
    // Ptr<NetDevice> clientRouterDevice = clientRouterDevices.Get(0);

    // clientRouterDevice->TraceConnectWithoutContext("Tx", MakeCallback(&LogPacketSize));

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
        std::string perAtkRateStr = datarate;
        StartDoSUdpClient(serverNodesAtk, attackerNode, routerServerInterfacesAtk, 30.0, 40.0, 40000, 2, perAtkRateStr); //to keep same IP for analysis
        StartDoSUdpClient(serverNodesAtk, attackerNode, routerServerInterfacesAtk, 70.0, 80.0, 49000, 2, perAtkRateStr); //to keep same IP for analysis
        StartDoSUdpClient(serverNodesAtk, attackerNode, routerServerInterfacesAtk, 110.0, 120.0, 44000, 2, perAtkRateStr); //to keep same IP for analysis
        StartDoSUdpClient(serverNodesAtk, attackerNode, routerServerInterfacesAtk, 150.0, 160.0, 46000, 2, perAtkRateStr); //to keep same IP for analysis
        NS_LOG_INFO("DoS Attack Enabled.");
        Simulator::Schedule(Seconds(0), &SetupAttackType, "9090", "1");
        Simulator::Schedule(Seconds(0), &SetupAttackType, "9091", "1");
    }
    if(lfaEnabled){
        // suffix = "lfa-drop";
        Simulator::Schedule(Seconds(0), &SetupAttackType, "9090", "2");
        Simulator::Schedule(Seconds(0), &SetupAttackType, "9091", "2");

        std::string perAtkRateStr = datarate;
        StartUdpFlows(serverNodesAtk, clientLfaNodes, routerServerInterfacesAtk, 30.0, 40.0, 40000, perAtkRateStr);
        // StartRandomUdpFlow(serverNodesAtk, clientLfaNodes, 30.0, 40.0, perAtkRateStr);
        // StartCoremeltAttack(serverNodesAtk, clientLfaNodes, routerServerInterfacesAtk, 30.0, 40.0, 1000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes8, clientLfaNodes, routerServerInterfaces8, 30.0, 40.0, 1000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes7, clientLfaNodes, routerServerInterfaces7, 30.0, 40.0, 1000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes6, clientLfaNodes, routerServerInterfaces6, 30.0, 40.0, 1000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes5, clientLfaNodes, routerServerInterfaces5, 30.0, 40.0, 1000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes4, clientLfaNodes, routerServerInterfaces4, 30.0, 40.0, 1000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes3, clientLfaNodes, routerServerInterfaces3, 30.0, 40.0, 1000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes2, clientLfaNodes, routerServerInterfaces2, 30.0, 40.0, 1000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes1, clientLfaNodes, routerServerInterfaces1, 30.0, 40.0, 1000, perAtkRateStr);

        StartUdpFlows(serverNodesAtk, clientLfaNodes, routerServerInterfacesAtk, 70.0, 80.0, 49000, perAtkRateStr);
        // StartRandomUdpFlow(serverNodesAtk, clientLfaNodes, 70.0, 80.0, perAtkRateStr);
        // StartCoremeltAttack(serverNodesAtk, clientLfaNodes, routerServerInterfacesAtk, 70.0, 80.0, 8000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes8, clientLfaNodes, routerServerInterfaces8, 70.0, 80.0, 8000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes7, clientLfaNodes, routerServerInterfaces7, 70.0, 80.0, 8000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes6, clientLfaNodes, routerServerInterfaces6, 70.0, 80.0, 8000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes5, clientLfaNodes, routerServerInterfaces5, 70.0, 80.0, 8000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes4, clientLfaNodes, routerServerInterfaces4, 70.0, 80.0, 8000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes3, clientLfaNodes, routerServerInterfaces3, 70.0, 80.0, 8000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes2, clientLfaNodes, routerServerInterfaces2, 70.0, 80.0, 8000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes1, clientLfaNodes, routerServerInterfaces1, 70.0, 80.0, 8000, perAtkRateStr);

        StartUdpFlows(serverNodesAtk, clientLfaNodes, routerServerInterfacesAtk, 110.0, 120.0, 44000, perAtkRateStr);
        // StartRandomUdpFlow(serverNodesAtk, clientLfaNodes, 110.0, 120.0, perAtkRateStr);
        // StartCoremeltAttack(serverNodesAtk, clientLfaNodes, routerServerInterfacesAtk, 110.0, 120.0, 15000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes8, clientLfaNodes, routerServerInterfaces8, 110.0, 120.0, 15000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes7, clientLfaNodes, routerServerInterfaces7, 110.0, 120.0, 15000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes6, clientLfaNodes, routerServerInterfaces6, 110.0, 120.0, 15000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes5, clientLfaNodes, routerServerInterfaces5, 110.0, 120.0, 15000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes4, clientLfaNodes, routerServerInterfaces4, 110.0, 120.0, 15000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes3, clientLfaNodes, routerServerInterfaces3, 110.0, 120.0, 15000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes2, clientLfaNodes, routerServerInterfaces2, 110.0, 120.0, 15000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes1, clientLfaNodes, routerServerInterfaces1, 110.0, 120.0, 15000, perAtkRateStr);

        StartUdpFlows(serverNodesAtk, clientLfaNodes, routerServerInterfacesAtk, 150.0, 160.0, 46000, perAtkRateStr);
        // StartRandomUdpFlow(serverNodesAtk, clientLfaNodes, 150.0, 160.0, perAtkRateStr);
        // StartCoremeltAttack(serverNodesAtk, clientLfaNodes, routerServerInterfacesAtk, 150.0, 160.0, 22000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes8, clientLfaNodes, routerServerInterfaces8, 150.0, 160.0, 22000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes7, clientLfaNodes, routerServerInterfaces7, 150.0, 160.0, 22000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes6, clientLfaNodes, routerServerInterfaces6, 150.0, 160.0, 22000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes5, clientLfaNodes, routerServerInterfaces5, 150.0, 160.0, 22000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes4, clientLfaNodes, routerServerInterfaces4, 150.0, 160.0, 22000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes3, clientLfaNodes, routerServerInterfaces3, 150.0, 160.0, 22000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes2, clientLfaNodes, routerServerInterfaces2, 150.0, 160.0, 22000, perAtkRateStr);
        // StartCoremeltAttack(serverNodes1, clientLfaNodes, routerServerInterfaces1, 150.0, 160.0, 22000, perAtkRateStr);
        NS_LOG_INFO("Link Flooding Attack Enabled.");
    }


    // csma.EnablePcapAll(outPcap+"/packets");  // Trace packets on server side
    p2p2.EnablePcap(outPcap+suffix, router3Router4Devices.Get(1), true);
    NS_LOG_INFO ("PCAP packets will be written in folder: " << outPcap);
    
    // Enable routing globally
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();


    // Run the simulation
    Simulator::Stop(Seconds(170));
    Simulator::Run();

    Simulator::Destroy();

    // ns3::MpiInterface::Disable();
    return 0;
}
