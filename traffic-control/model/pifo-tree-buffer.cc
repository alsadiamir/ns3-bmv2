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
 *
 */

#include <string>

#include "ns3/log.h"
#include "ns3/object-factory.h"
#include "json/json.h"
#include "pifo-tree-buffer.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("PifoTreeBuffer");

NS_OBJECT_ENSURE_REGISTERED (PifoTreeBuffer);

TypeId PifoTreeBuffer::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::PifoTreeBuffer")
    .SetParent<QueueDisc> ()
    .SetGroupName ("TrafficControl")
    .AddConstructor<PifoTreeBuffer> ()
    // TODO(sibanez): Add trace callback to track enqueues and dequeues into a buffer partition
  ;
  return tid;
}

PifoTreeBuffer::PifoTreeBuffer ()
{
  NS_LOG_FUNCTION (this);
}

PifoTreeBuffer::~PifoTreeBuffer ()
{
  NS_LOG_FUNCTION (this);
}

bool
PifoTreeBuffer::Configure (Json::Value configRoot)
{
  NS_LOG_FUNCTION (this);

/*
  Sample config:

  "num-bufIDs" : 3,
  "buffer-sizes" : [10000],
  "bufID-map" :
  {
      "0" : [0],
      "1" : [0],
      "2" : [0]
  }
*/

  // initialize the buffers
  Json::Value bufSizes = configRoot["partition-sizes"];
  for (int i = 0; i < bufSizes.size (); i++)
    {
      uint32_t limit = bufSizes[i].asInt ();
      m_partitionLimits.push_back(limit);
      m_partitions.push_back (0);
    }

  // initialize the bufIDMap
  uint32_t numBufIDs = configRoot["num-bufIDs"].asInt ();
  Json::Value mapConfig = configRoot["bufID-map"];
  for (int i = 0; i < numBufIDs; i++)
    {
      Json::Value indicies = mapConfig[std::to_string(i)];
      for (int j = 0; j < indicies.size (); j++)
        {
          m_bufIDMap[i].push_back (indicies[j].asInt ());
        }
    }

}

bool
PifoTreeBuffer::Enqueue (uint32_t bufID, Ptr<QueueDiscItem> item, sched_meta_t& sched_meta)
{
  NS_LOG_FUNCTION (this);

  if (!m_bufIDMap.contains[bufID])
    {
      NS_LOG_ERROR ("Attempted to enqueue into invalid buffer ID " << bufID);
      return false;
    }

  // check each possible partition in order for space
  for (int i = 0; i < m_bufIDMap[bufID].size (); i++)
    {
      uint32_t partitionID = m_bufIDMap[bufID][i];
      if (m_partitions[partitionID] + item->GetSize () <= m_partitionLimits[partitionID])
        {
          m_partitions[partitionID] += item->GetSize ();
          // TODO(sibanez): set buffer related scheduling metadata fields
          sched_meta.partition_id = i;
          sched_meta.partition_size = m_partitions[partitionID];
          sched_meta.partition_max_size = m_partitionLimits[partitionID];
          return true;
        }
    }
  return false;
}

bool
PifoTreeBuffer::Dequeue (uint32_t partitionID, Ptr<QueueDiscItem> item)
{
  NS_LOG_FUNCTION (this);

  if (partitionID >= m_partitions.size ())
    {
      NS_LOG_ERROR ("Attempted to dequeue from an invalid partition " << partitionID);
      return false;
    }

  if (m_partitions[partitionID] < item->GetSize ())
    {
      NS_LOG_ERROR ("Attempted to dequeue too much from partition " << partitionID);
      return false;
    }

  m_partitions[partitionID] -= item->GetSize ();
  return true;
}

} // namespace ns3