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
                    StringValue (""), MakeStringAccessor (&V1ModelP4Queue::GetCommandsFile, &V1ModelP4Queue::SetCommandsFile), MakeStringChecker ());
    return tid;
  }

  V1ModelP4Queue::V1ModelP4Queue ()
  {
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


} // namespace ns3