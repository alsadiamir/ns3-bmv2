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
 * Authors: Stephen Ibanez <sibanez@stanford.edu>
 */

#include "ns3/v1model-p4-pipeline.h"
#include "v1model-p4-queue.h"
#include "ns3/packet.h"
#include "ns3/string.h"

namespace ns3 {

  TypeId
  V1ModelP4Queue::GetTypeId (void)
  {
    static TypeId tid = TypeId ("ns3::V1ModelP4Queue")
      .SetParent<Queue<Packet>> ()
      .SetGroupName ("TrafficControl")
      .AddConstructor<V1ModelP4Queue> ()
      .AddAttribute ( "JsonFile", "The bmv2 JSON file to use",
                    StringValue (""), MakeStringAccessor (&V1ModelP4Queue::GetJsonFile, &V1ModelP4Queue::SetJsonFile), MakeStringChecker ())
      .AddAttribute ( "CommandsFile", "A file with CLI commands to run on the P4 pipeline before starting the simulation",
                    StringValue (""), MakeStringAccessor (&V1ModelP4Queue::GetCommandsFile, &V1ModelP4Queue::SetCommandsFile), MakeStringChecker ())
      .AddAttribute ( "DeprioritizationEnabled", "Enable deprioritization of packets",
                    BooleanValue (false), MakeBooleanAccessor (&V1ModelP4Queue::GetDeprioritizationEnabled, &V1ModelP4Queue::SetDeprioritizationEnabled), MakeBooleanChecker ())
      .AddAttribute ( "MaxQueueSize", "The maximum size of the queue",
                    UintegerValue (100), MakeUintegerAccessor (&V1ModelP4Queue::SetMaxQueueSize), MakeUintegerChecker<uint32_t> ())
      .AddAttribute ( "MinThreshold", "The minimum threshold for the queue",
                    UintegerValue (70), MakeUintegerAccessor (&V1ModelP4Queue::SetMinThreshold), MakeUintegerChecker<uint32_t> ())
      .AddAttribute ( "MaxThreshold", "The maximum threshold for the queue",
                    UintegerValue (90), MakeUintegerAccessor (&V1ModelP4Queue::SetMaxThreshold), MakeUintegerChecker<uint32_t> ())
      .AddAttribute ( "LogEnabled", "Enable logging of queue operations",
                    BooleanValue (false), MakeBooleanAccessor (&V1ModelP4Queue::GetLogEnabled, &V1ModelP4Queue::SetLogEnabled), MakeBooleanChecker ());
    return tid;
  }

  V1ModelP4Queue::V1ModelP4Queue ()
  {
    m_priorityQueue1 = CreateObject<DropTailQueue<Packet>> ();
    m_priorityQueue2 = CreateObject<DropTailQueue<Packet>> ();
    m_priorityQueue3 = CreateObject<DropTailQueue<Packet>> ();
    m_priorityQueue4 = CreateObject<DropTailQueue<Packet>> ();

  }

  V1ModelP4Queue::~V1ModelP4Queue ()
  {
    delete m_p4Pipe;
  }

  std::string
  V1ModelP4Queue::GetJsonFile (void) const
  {
    // NS_LOG_FUNCTION (this);
    return m_jsonFile;
  }

  void
  V1ModelP4Queue::SetJsonFile (std::string jsonFile)
  {
    // NS_LOG_FUNCTION (this << jsonFile);
    m_jsonFile = jsonFile;
  }

  std::string
  V1ModelP4Queue::GetCommandsFile (void) const
  {
    // NS_LOG_FUNCTION (this);
    return m_commandsFile;
  }

  void
  V1ModelP4Queue::SetCommandsFile (std::string commandsFile)
  {
    // NS_LOG_FUNCTION (this << commandsFile);
    m_commandsFile = commandsFile;
  }

  bool
  V1ModelP4Queue::GetDeprioritizationEnabled (void) const
  {
    return m_deprioritizationEnabled;
  }

  void
  V1ModelP4Queue::SetDeprioritizationEnabled (bool enabled)
  {
    m_deprioritizationEnabled = enabled;
  }

  void
  V1ModelP4Queue::SetMaxQueueSize (uint32_t maxSize)
  {
    m_maxQueueSize = maxSize;
    m_priorityQueue1->SetMaxSize (QueueSize (QueueSizeUnit::PACKETS, maxSize));
    m_priorityQueue2->SetMaxSize (QueueSize (QueueSizeUnit::PACKETS, maxSize));
    m_priorityQueue3->SetMaxSize (QueueSize (QueueSizeUnit::PACKETS, maxSize));
    m_priorityQueue4->SetMaxSize (QueueSize (QueueSizeUnit::PACKETS, maxSize));
    // SetMaxSize (QueueSize(QueueSizeUnit::PACKETS, UINT32_MAX));
  }

  void 
  V1ModelP4Queue::SetMinThreshold (uint32_t minThreshold)
  {
    m_minThreshold = minThreshold;
  }

  void
  V1ModelP4Queue::SetMaxThreshold (uint32_t maxThreshold)
  {
    m_maxThreshold = maxThreshold;
  }

  void
  V1ModelP4Queue::SetOutPath (std::string outPath)
  {
    std::ofstream outputFile(outPath, std::ios::out);

    // Check if the file was successfully opened
    if (!outputFile) {
        std::cerr << "Error opening output file!" << std::endl;
    }
    else{
      outputFile << std::endl;
      m_outPath = outPath;
    }

    std::ofstream outputFileLog(outPath+".log", std::ios::out);

    // Check if the file was successfully opened
    if (!outputFileLog) {
        std::cerr << "Error opening output file .log!" << std::endl;
    }
    else{
      outputFileLog << std::endl;
    }
    
  }

  bool
  V1ModelP4Queue::GetLogEnabled (void) const
  {
    return m_logEnabled;
  }

  void
  V1ModelP4Queue::SetLogEnabled (bool enabled)
  {
    m_logEnabled = enabled;
  }

} // namespace ns3