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

#include "ns3/log.h"
#include "ns3/pointer.h"
#include "ns3/object-factory.h"
#include "ns3/socket.h"
#include "ns3/string.h"
#include "ns3/simulator.h"
#include "ns3/v1model-p4-pipeline.h"
#include "v1model-p4-queue-disc.h"
#include "ns3/ipv4-header.h"
#include "ns3/tcp-header.h"
#include <algorithm>
#include <iterator>
#include <chrono>
#include <thread>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("V1ModelP4QueueDisc");

NS_OBJECT_ENSURE_REGISTERED (V1ModelP4QueueDisc);

// Initialize static members
Ptr<Packet> V1ModelP4QueueDisc::default_packet = Create<Packet> ();

TypeId V1ModelP4QueueDisc::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::V1ModelP4QueueDisc")
    .SetParent<QueueDisc> ()
    .SetGroupName ("Network")
    .AddConstructor<V1ModelP4QueueDisc> ()
    .AddAttribute ("MaxSize",
                   "The max queue size",
                   QueueSizeValue (QueueSize ("500KB")),
                   MakeQueueSizeAccessor (&QueueDisc::SetMaxSize,
                                          &QueueDisc::GetMaxSize),
                   MakeQueueSizeChecker ())
    .AddAttribute ( "JsonFile", "The bmv2 JSON file to use",
                    StringValue (""), MakeStringAccessor (&V1ModelP4QueueDisc::GetJsonFile, &V1ModelP4QueueDisc::SetJsonFile), MakeStringChecker ())
    .AddAttribute ( "CommandsFile", "A file with CLI commands to run on the P4 pipeline before starting the simulation",
                    StringValue (""), MakeStringAccessor (&V1ModelP4QueueDisc::GetCommandsFile, &V1ModelP4QueueDisc::SetCommandsFile), MakeStringChecker ())
    .AddAttribute ( "EnableDropEvents",
                    "Enable drop event triggers in P4 pipeline",
                    BooleanValue (false), // default disabled
                    MakeBooleanAccessor (&V1ModelP4QueueDisc::m_enDropEvents),
                    MakeBooleanChecker ())
    .AddAttribute ( "EnableEnqueueEvents",
                    "Enable enqueue event triggers in P4 pipeline",
                    BooleanValue (false), // default disabled
                    MakeBooleanAccessor (&V1ModelP4QueueDisc::m_enEnqEvents),
                    MakeBooleanChecker ())
    .AddAttribute ( "EnableDequeueEvents",
                    "Enable dequeue event triggers in P4 pipeline",
                    BooleanValue (false), // default disabled
                    MakeBooleanAccessor (&V1ModelP4QueueDisc::m_enDeqEvents),
                    MakeBooleanChecker ())
  ;
  return tid;
}

V1ModelP4QueueDisc::V1ModelP4QueueDisc ()
  : QueueDisc (QueueDiscSizePolicy::SINGLE_CHILD_QUEUE_DISC, QueueSizeUnit::BYTES)
{
  NS_LOG_FUNCTION (this);
  m_p4Pipe = NULL; 
}

V1ModelP4QueueDisc::~V1ModelP4QueueDisc ()
{
  NS_LOG_FUNCTION (this);
  delete m_p4Pipe;
}

std::string
V1ModelP4QueueDisc::GetJsonFile (void) const
{
  NS_LOG_FUNCTION (this);
  return m_jsonFile;
}

void
V1ModelP4QueueDisc::SetJsonFile (std::string jsonFile)
{
  NS_LOG_FUNCTION (this << jsonFile);
  m_jsonFile = jsonFile;
}

std::string
V1ModelP4QueueDisc::GetCommandsFile (void) const
{
  NS_LOG_FUNCTION (this);
  return m_commandsFile;
}

void
V1ModelP4QueueDisc::SetCommandsFile (std::string commandsFile)
{
  NS_LOG_FUNCTION (this << commandsFile);
  m_commandsFile = commandsFile;
}

void
V1ModelP4QueueDisc::InitStdMeta (std_meta_t &std_meta)
{
  //
  // Initialize standard metadata
  //
  std_meta.ingress_port = 0;
  std_meta.egress_spec = 0;
  std_meta.egress_port = 0;

  std_meta.instance_type = 0;
  std_meta.packet_length = 0;

  // queueing metadata
  std_meta.enq_timestamp = 0;
  std_meta.enq_qdepth = 0;
  std_meta.deq_timedelta = 0;
  std_meta.deq_qdepth = 0;

  // intrinsic metadata
  std_meta.ingress_global_timestamp = 0;
  std_meta.egress_global_timestamp = 0;
  std_meta.mcast_grp = 0;
  std_meta.egress_rid = 0;
  std_meta.checksum_error = false;
  std_meta.parser_error = 0;
  std_meta.priority = 0;
}

void
V1ModelP4QueueDisc::InspectPacket (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  TcpHeader tcpHeader;
  if (packet->PeekHeader (tcpHeader))
    {
      std:: cout << "TCP Header: srcPort=" << tcpHeader.GetSourcePort () << ", dstPort=" << tcpHeader.GetDestinationPort () << std::endl;
    }

  // Example: Inspect IPv4 header
  // Ipv4Header ipv4Header;
  // if (packet->PeekHeader (ipv4Header))
  //   {
  //     NS_LOG_INFO ("IPv4 Header: src=" << ipv4Header.GetSource () << ", dst=" << ipv4Header.GetDestination ());
      
  //     // // Inspect transport layer headers
  //     // if (ipv4Header.GetProtocol () == Ipv4Header::PROT_UDP)
  //     //   {
  //     //     UdpHeader udpHeader;
  //     //     if (packet->PeekHeader (udpHeader))
  //     //       {
  //     //         NS_LOG_INFO ("UDP Header: srcPort=" << udpHeader.GetSourcePort () << ", dstPort=" << udpHeader.GetDestinationPort ());
  //     //       }
  //     //   }
  //     // else 
  //     if (ipv4Header.GetProtocol () == 6)
  //       {
  //         TcpHeader tcpHeader;
  //         if (packet->PeekHeader (tcpHeader))
  //           {
  //             NS_LOG_INFO ("TCP Header: srcPort=" << tcpHeader.GetSourcePort () << ", dstPort=" << tcpHeader.GetDestinationPort ());
  //           }
  //       }
  //   }
}

bool
V1ModelP4QueueDisc::DoEnqueue (Ptr<QueueDiscItem> item)
{
  NS_LOG_FUNCTION (this << item);

  // InspectPacket (item->GetPacket () -> Copy ());

  // std::cout << "Starting enqueuing" << std::endl;

  // TODO(sibanez): potentially need to cancel the timer event
  // if there is one scheduled for this time slot and it has
  // not executed yet. The problem is: what if there was a timer
  // event scheduled for this time slot but it already executed?
  // Since we are not doing any timer event canceling for now
  // this means that we could end up with both legit and generated
  // packets being processed by the P4 pipeline in the same time slot

  //
  // Compute average queue size
  //

  //
  // Initialize standard metadata
  //
  std::cout << item->GetPacket()->ToString() << std::endl;

  std_meta_t std_meta;
  InitStdMeta (std_meta);

  // perform P4 processing
  Ptr<Packet> new_packet = m_p4Pipe->process_pipeline(item->GetPacket(), std_meta, 0, 0);

  // std::cout << std_meta.egress_spec << std::endl;
  
  // replace the QueueDiscItem's packet
  item->SetPacket(new_packet);

  // std::cout << item->GetPacket()->ToString() << std::endl;

  if (std_meta.egress_spec == 511)
    {
      // std::cout << "Dropping packet because P4 program said to" << std::endl;
      NS_LOG_DEBUG ("Dropping packet because P4 program said to");
      DropBeforeEnqueue (item, P4_DROP);
      return false;
    }

  // set enqueue timestamp
  item->SetTimeStamp (Simulator::Now());

  bool retval = GetQueueDiscClass (0)->GetQueueDisc ()->Enqueue (item);

  // If Queue::Enqueue fails, QueueDisc::Drop is called by the child queue disc
  // because QueueDisc::AddQueueDiscClass sets the drop callback

  NS_LOG_LOGIC ("Number packets in queue disc " << GetQueueDiscClass (0)->GetQueueDisc ()->GetNPackets ());
  // std::cout << "Ending enqueuing" << std::endl;

  return retval;
}

Ptr<QueueDiscItem>
V1ModelP4QueueDisc::DoDequeue (void)
{
  NS_LOG_FUNCTION (this);

  if (GetQueueDiscClass (0)->GetQueueDisc ()->GetNPackets() == 0)
    {
      NS_LOG_LOGIC ("Queue empty");

      return 0;
    }
  else
    {
      Ptr<QueueDiscItem> item;
      item = GetQueueDiscClass (0)->GetQueueDisc ()->Dequeue ();

      NS_LOG_LOGIC ("Popped from qdisc: " << item);
      NS_LOG_LOGIC ("Number packets in qdisc: " << GetQueueDiscClass (0)->GetQueueDisc ()->GetNPackets ());

      return item;
    }
}

Ptr<const QueueDiscItem>
V1ModelP4QueueDisc::DoPeek (void)
{
  NS_LOG_FUNCTION (this);

  Ptr<const QueueDiscItem> item;

  if ((item = GetQueueDiscClass (0)->GetQueueDisc ()->Peek ()) != 0)
    {
      NS_LOG_LOGIC ("Peeked from qdisc: " << item);
      NS_LOG_LOGIC ("Number packets band: " << GetQueueDiscClass (0)->GetQueueDisc ()->GetNPackets ());
      return item;
    }

  NS_LOG_LOGIC ("Queue empty");
  return item;
}

void
V1ModelP4QueueDisc::RunDropEvent (Ptr<const QueueDiscItem> item)
{
  //
  // Initialize standard metadata
  //
  std_meta_t std_meta;
  InitStdMeta (std_meta);
  
  // perform P4 processing
  m_p4Pipe->process_pipeline(default_packet, std_meta, 0, 0);
}

void
V1ModelP4QueueDisc::InitializeParams (void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO ("Initializing P4 Queue Disc params.");

  std:: cout << "Initializing P4 Queue Disc params." << std::endl;

  // create and initialize the P4 pipeline
  if (m_p4Pipe == NULL && m_jsonFile != "" && m_commandsFile != "")
    {
      m_p4Pipe = new V1ModelP4Pipe(m_jsonFile);
      m_p4Pipe->run_cli (m_commandsFile);
    }
}

bool
V1ModelP4QueueDisc::CheckConfig (void)
{
  NS_LOG_FUNCTION (this);
  if (GetNInternalQueues () > 0)
    {
      NS_LOG_ERROR ("V1ModelP4QueueDisc cannot have internal queues");
      return false;
    }

  if (GetNPacketFilters () > 0)
    {
      NS_LOG_ERROR ("V1ModelP4QueueDisc cannot have any packet filters");
      return false;
    }

  if (GetNQueueDiscClasses () == 0)
    {
      // create 1 fifo queue disc
      ObjectFactory factory;
      factory.SetTypeId ("ns3::FifoQueueDisc");
      Ptr<QueueDisc> qd = factory.Create<QueueDisc> ();

      if (!qd->SetMaxSize (GetMaxSize ()))
        {
          NS_LOG_ERROR ("Cannot set the max size of the child queue disc to that of V1ModelP4QueueDisc");
          return false;
        }
      qd->Initialize ();
      Ptr<QueueDiscClass> c = CreateObject<QueueDiscClass> ();
      c->SetQueueDisc (qd);
      AddQueueDiscClass (c);
    }

  if (GetNQueueDiscClasses () != 1)
    {
      NS_LOG_ERROR ("V1ModelP4QueueDisc requires exactly 1 class");
      return false;
    }

  if (m_jsonFile == "")
    {
      NS_LOG_ERROR ("V1ModelP4QueueDisc is not configured with a JSON file");
      return false;
    }

  if (m_commandsFile == "")
    {
      NS_LOG_ERROR ("V1ModelP4QueueDisc is not configured with a CLI commands file");
      return false;
    }

  // Check if drop events are enabled
  if (m_enDropEvents)
    {
      TraceConnectWithoutContext ("DropBeforeEnqueue", MakeCallback (&V1ModelP4QueueDisc::RunDropEvent, this));
    }

  // Check if enqueue events are enabled
  // if (m_enEnqEvents)
  //   {
  //     TraceConnectWithoutContext ("Enqueue", MakeCallback (&V1ModelP4QueueDisc::RunEnqEvent, this));
  //   }

  // // Check if dequeue events are enabled
  // if (m_enDeqEvents)
  //   {
  //     TraceConnectWithoutContext ("Dequeue", MakeCallback (&V1ModelP4QueueDisc::RunDeqEvent, this));
  //   }

  return true;
}

} // namespace ns3