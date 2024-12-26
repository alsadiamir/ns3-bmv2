/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018 Stanford University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Stephen Ibanez <sibanez@stanford.edu>
 */

#ifndef V1MODELP4_QUEUE_H
#define V1MODELP4_QUEUE_H

// #include "ns3/queue-disc.h"
// #include "ns3/nstime.h"
#include "ns3/packet.h"
#include "ns3/queue.h"
#include "ns3/simulator.h"
#include "ns3/v1model-p4-pipeline.h"
#include "ns3/random-variable-stream.h"
#include "ns3/drop-tail-queue.h"
#include <array>
#include <string>
#include <list>
#include <iostream>
#include <fstream>

namespace ns3 {


/**
 * \ingroup traffic-control
 *
 * The P4 qdisc is configured by a P4 program. It contains qdisc classes
 * which actually perform the queueing and scheduling. This qdisc is
 * intended to be the root qdisc that simply runs the user's P4 program
 * and then passes the modified packet to the appropriate qdisc class
 * (or drops the packet if the P4 program says to do so).
 */
  class V1ModelP4Queue : public Queue<Packet>
  {
  public:
    static TypeId GetTypeId (void);
    V1ModelP4Queue ();
    virtual ~V1ModelP4Queue ();
    /// Get the JSON source file
    std::string GetJsonFile (void) const;

    /// Set the JSON source file
    void SetJsonFile (std::string jsonFile);

    /// Get the CLI commands file 
    std::string GetCommandsFile (void) const;

    /// Set the CLI commands file
    void SetCommandsFile (std::string commandsFile);

    /// Get the deprioritization enabled flag
    bool GetDeprioritizationEnabled (void) const;
    bool GetLogEnabled (void) const;

    /// Set the deprioritization enabled flag
    void SetDeprioritizationEnabled (bool deprioritizationEnabled);

    void SetOutPath (std::string outPath);

    void SetMaxQueueSize (uint32_t maxQueueSize);
    void SetMinThreshold (uint32_t minThreshold);
    void SetMaxThreshold (uint32_t maxThreshold);
    void SetLogEnabled (bool logEnabled);


    virtual bool Enqueue (Ptr<Packet> packet) override
    {
      return DoEnqueue (packet);
    }

    virtual Ptr<Packet> Dequeue (void) override
    {
      return DoDequeue ();
    }

    void
    LogOnFile (uint32_t priority, uint32_t protocol, std::string phase, bool dropped = false)
    {
      if(m_logEnabled == false) {
        return;
      } else{
        std::ofstream m_outputFile(m_outPath, std::ios::app);  // Open file in append mode
        std::string proto = "IPv4";
        std::string msgStart = "Enqueued";
        if (protocol == 17) {
          proto = "UDP"; 
        } else if (protocol == 6) {
          proto = "TCP";
        }

        if (m_outputFile.is_open()) {
          if(dropped) {
            m_outputFile << phase << " Dropped packet with protocol: " << proto << std::endl;
          } else {
            if (phase == "[DEQUEUE]"){
              msgStart = "Dequeued";
            }
            m_outputFile << phase << " " << msgStart << " packet in (prio" << priority << ") with protocol: " << proto << std::endl;
            m_outputFile << "Time:" << Simulator::Now().GetSeconds() << " QUEUE (prio0): " << m_priorityQueue1->GetNPackets() << " QUEUE (prio1): " << m_priorityQueue2->GetNPackets() << " QUEUE (prio2): " << m_priorityQueue3->GetNPackets() << " QUEUE (prio3): " << m_priorityQueue4->GetNPackets() << std::endl;
            m_outputFile.close();  // Close file
          }
        }
        m_outputFile.close();  // Close file
      }
    }

    void DebugStat4(std::string port, std::string log_file, std::string msg){
      std::ofstream outputFile(log_file, std::ios::app);  // Open file in append mode
      if (outputFile.is_open()) {
        outputFile << msg << Simulator::Now().GetSeconds() << std::endl;
      }
      std::string cmd = "echo \"register_read tmp_stats_freq_internal\" | simple_switch_CLI --thrift-port "+port+" >> " + log_file;
      std::system(cmd.c_str());
    }

    virtual bool DoEnqueue (Ptr<Packet> packet)
    {
      std_meta_t std_meta;
      std_meta.ingress_global_timestamp = Simulator::Now ().GetMicroSeconds ();
      std_meta.packet_length = packet->GetSize ();
      Ptr<Packet> new_packet = m_p4Pipe->process_pipeline(packet, std_meta, 0, 0);
      bool result = false;
      uint16_t priority = std_meta.egress_spec; // Dummy logic for assigning priority
      uint16_t spec = std_meta.priority;
      if(spec == 4){
        DebugStat4("9090", m_outPath, "Spike detected at: ");
      } 
      if(spec == 5){
        DebugStat4("9091", m_outPath, "First drill down at: ");
      }  
      if(spec == 6){
        DebugStat4("9091", m_outPath, "Second drill down at: ");
      }    
      if(m_deprioritizationEnabled == true) {   
        switch (priority)
        {
            case 0:
                if(m_priorityQueue1->GetNPackets() >= m_maxQueueSize){
                  LogOnFile(priority, std_meta.instance_type, "[ENQUEUE]", true);
                  return false;
                }
                result = m_priorityQueue1->Enqueue (new_packet);
                break;
            case 1:
                if(m_priorityQueue2->GetNPackets() >= m_maxQueueSize){
                  LogOnFile(priority, std_meta.instance_type, "[ENQUEUE]", true);
                  return false;
                }
                result = m_priorityQueue2->Enqueue (new_packet);
                break;
            case 2:
                if(m_priorityQueue3->GetNPackets() >= m_maxQueueSize){
                  LogOnFile(priority, std_meta.instance_type, "[ENQUEUE]", true);
                  return false;
                }
                result = m_priorityQueue3->Enqueue (new_packet);
                break;
            default:
                if(m_priorityQueue4->GetNPackets() >= m_maxQueueSize){
                  LogOnFile(priority, std_meta.instance_type, "[ENQUEUE]", true);
                  return false;
                }
                result = m_priorityQueue4->Enqueue (new_packet);
                break;
        }
        if (priority > 3){
          priority = 3;
        }
        LogOnFile(priority, std_meta.instance_type, "[ENQUEUE]", false);
        return result;
      }               
      else {       
        if(priority == 511) {
            // std::cout << "Dropped packet because P4 said so!" << std::endl;
            return false;
        } else if (priority == 0){
          result = m_priorityQueue1->Enqueue (new_packet);
        } else{
          result = m_priorityQueue2->Enqueue (new_packet);
        }
        // if(m_priorityQueue1->GetNPackets() >= m_maxQueueSize){
        //   LogOnFile(priority, std_meta.instance_type, "[ENQUEUE]", true);
        //   return false;
        // }
        // result = m_priorityQueue1->Enqueue (new_packet);
        return result;
      }
      return false;
    }

    virtual Ptr<Packet> DoDequeue (void)
    {
        Ptr<Packet> packet = nullptr;
        uint32_t priority = 4;

        // Check highest priority first, moving down to lowest
        if (!m_priorityQueue1->IsEmpty ())
        {
            priority = 0;
            packet = m_priorityQueue1->Dequeue ();
        }
        else if (!m_priorityQueue2->IsEmpty ())
        {
            priority = 1;
            packet = m_priorityQueue2->Dequeue ();
        }
        else if (!m_priorityQueue3->IsEmpty ())
        {
            priority = 2;
            packet = m_priorityQueue3->Dequeue ();
        }
        else if (!m_priorityQueue4->IsEmpty ())
        {
            priority = 3;
            packet = m_priorityQueue4->Dequeue ();
        }
        if(priority < 4){
          LogOnFile(priority, 0, "[DEQUEUE]", false);
        }

        return packet;
    }
    
    virtual Ptr<const Packet> Peek (void) const override
    {
      return DoPeek (Head ());
    }
    
    virtual Ptr<Packet> Remove (void) override
    {
      Ptr<Packet> packet = DoRemove (Head ());
      // NS_LOG_INFO ("V1ModelP4Queue::Remove called with packet of size: " << packet->GetSize ());
      return packet;
    }
    
    void CreateP4Pipe(std::string m_jsonFile, std::string m_commandsFile) 
    {
      // NS_LOG_INFO ("Initializing P4 Queue Disc params.");

      V1ModelP4Pipe *p4Pipe = new V1ModelP4Pipe(m_jsonFile);
      p4Pipe->run_cli (m_commandsFile);
      m_p4Pipe = p4Pipe;
      m_startingTime = Simulator::Now ().GetMicroSeconds ();
    }

    double
    CalculateDropProbability (uint32_t queueSize, uint32_t priority)
    {
      if (queueSize < m_minThreshold || priority < 3)
        {
          return 0.0;  // No drops if below min threshold
        }

      // Calculate probability based on queue size
      double prob = (double(queueSize) - m_minThreshold) / (m_maxThreshold - m_minThreshold);
      prob *= (1 + 1/double(4-priority));
      // std::cout << "Priority: " << priority << " Prob: " << prob << std::endl;
      
      return std::min (prob, 1.0);  // Cap the probability at 1
    }
    
    private:
      // using Queue<Packet>::Head;
      // using Queue<Packet>::Tail;
      // using Queue<Packet>::DoEnqueue;
      // using Queue<Packet>::DoDequeue;
      // using Queue<Packet>::DoRemove;
      // using Queue<Packet>::DoPeek;
      V1ModelP4Pipe *m_p4Pipe;            //!< The P4 pipeline
      std::string m_jsonFile;      //!< The bmv2 JSON file (generated by the p4c-bm backend)
      std::string m_commandsFile;  //!< The CLI commands file
      std::string m_outPath;  // Output file path
      int m_port;             //!< The port number
      int64_t m_startingTime;
      std::list<std::pair<Ptr<Packet>,uint8_t>> m_queue;  // List of packets and their priority
      bool m_deprioritizationEnabled = false;  //!< Enable deprioritization of packets
      bool m_logEnabled = false;  // Enable logging
      uint32_t m_minThreshold;  // Minimum threshold for RED
      uint32_t m_maxThreshold;  // Maximum threshold for RED / 4
      uint32_t m_maxQueueSize;  // Maximum queue size
      Ptr<UniformRandomVariable> m_rand = CreateObject<UniformRandomVariable> (); // Random variable for probabilistic drops

      Ptr<DropTailQueue<Packet>> m_priorityQueue1; // Highest priority
      Ptr<DropTailQueue<Packet>> m_priorityQueue2;
      Ptr<DropTailQueue<Packet>> m_priorityQueue3;
      Ptr<DropTailQueue<Packet>> m_priorityQueue4; // Lowest priority
      // std::ofstream m_outputFile("output.txt");
  };
}

#endif /* V1MODELP4_QUEUE_H */