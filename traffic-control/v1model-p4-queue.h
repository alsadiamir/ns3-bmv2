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
#include <array>
#include <string>
#include <list>

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

    /// Set the deprioritization enabled flag
    void SetDeprioritizationEnabled (bool deprioritizationEnabled);

    void SetMaxQueueSize (uint32_t maxQueueSize);
    void SetMinThreshold (uint32_t minThreshold);
    void SetMaxThreshold (uint32_t maxThreshold);

    virtual bool Enqueue (Ptr<Packet> packet) override
    {
      return DoEnqueue (packet);
    }

    virtual Ptr<Packet> Dequeue (void) override
    {
      return DoDequeue ();
    }

    virtual bool DoEnqueue (Ptr<Packet> packet)
    {
      std_meta_t std_meta;
      std_meta.ingress_global_timestamp = Simulator::Now ().GetMicroSeconds ();
      Ptr<Packet> new_packet = m_p4Pipe->process_pipeline(packet, std_meta, 0, 0);
      
      if(m_deprioritizationEnabled == true) {
          // uint32_t queueSize = GetNPackets ();
  
          // // RED Drop logic
          // if (queueSize >= m_maxQueueSize)
          //   {
          //     std::cout << "Queue full! Dropping packet" << std::endl;
          //     return false;  // Drop packet if the queue is full
          //   }
          
          // double dropProb = CalculateDropProbability (queueSize, std_meta.egress_spec);

          // // if (dropProb > 0) {
          // //   std::cout << "Queue Size: " << queueSize << " Drop probability: " << dropProb << " Priority: " << std_meta.egress_spec << std::endl;
          // // }
          // // std::cout << "Queue Size: " << queueSize << " Drop probability: " << dropProb << std::endl;

          // // Randomly drop packet based on probability
          // if (dropProb > 0.0 && m_rand->GetValue () < dropProb)
          //   {
          //     std::cout << "Dropping packet based on RED probability" << " Priority: " << std_meta.egress_spec << std::endl;
          //     return false;  // Drop packet
          //   }
          // return Queue<Packet>::DoEnqueue (Tail (), new_packet);
          
          // uint32_t queueSize = m_queue.size ();
          // if (queueSize > 10) {
          //   std::cout << "Queue Size: " << m_queue.size () << std::endl;
          // }
          auto it = m_queue.begin ();
          while (it != m_queue.end () && it->second <= std_meta.egress_spec)
            {
              ++it;  // Find the correct position to insert based on priority
            }
          
          // Insert the packet with its priority in the correct position
          m_queue.insert (it, std::make_pair (new_packet, std_meta.egress_spec));
          
          // Ptr<Packet> toEnqueue = m_queue.front ().first;

          return Queue<Packet>::DoEnqueue (Tail (), new_packet);
      }
      else {
        if(std_meta.egress_spec == 511) {
            std::cout << "Dropped packet!" << std::endl;
            return false;
          } 
        return Queue<Packet>::DoEnqueue (Tail (), new_packet);
      }
      return false;
    }

    virtual Ptr<Packet> DoDequeue (void)
    {
      
      // uint32_t queueSize = GetNPackets ();
      // std::cout << "Out Queue Size: " << queueSize << std::endl;
      if(m_deprioritizationEnabled == true) {
        if (m_queue.empty ()) 
        {
          return 0;
        }
        Ptr<Packet> packet = m_queue.front ().first;
        // uint32_t priority = m_queue.front ().second;
        // std::cout << "Dequeued packet with priority: " << priority << std::endl;
        m_queue.pop_front ();
        return packet;
      }
      return Queue<Packet>::DoDequeue (Head ()); // no deprioritization
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
      using Queue<Packet>::Head;
      using Queue<Packet>::Tail;
      using Queue<Packet>::DoEnqueue;
      using Queue<Packet>::DoDequeue;
      using Queue<Packet>::DoRemove;
      using Queue<Packet>::DoPeek;
      V1ModelP4Pipe *m_p4Pipe;            //!< The P4 pipeline
      std::string m_jsonFile;      //!< The bmv2 JSON file (generated by the p4c-bm backend)
      std::string m_commandsFile;  //!< The CLI commands file
      int m_port;             //!< The port number
      int64_t m_startingTime;
      std::list<std::pair<Ptr<Packet>, uint8_t>> m_queue;  // List of packets and their priority
      bool m_deprioritizationEnabled;  //!< Enable deprioritization of packets
      uint32_t m_minThreshold;  // Minimum threshold for RED
      uint32_t m_maxThreshold;  // Maximum threshold for RED / 4
      uint32_t m_maxQueueSize;  // Maximum queue size
      Ptr<UniformRandomVariable> m_rand = CreateObject<UniformRandomVariable> (); // Random variable for probabilistic drops
  };
}

#endif /* V1MODELP4_QUEUE_H */