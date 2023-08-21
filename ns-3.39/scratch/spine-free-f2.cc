/*
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
 */

/**
 * \file
 * \ingroup mpi
 *
 * This script creates a dumbbell topology and logically splits it in half. The
 * left half is placed on logical processor 0 and the right half is placed on
 * logical processor 1. The number of nodes are configurable.
 *
 *                 -------   -------
 *                  RANK 0    RANK 1
 *                 ------- | -------
 *                         |
 * n0 ---------|           |           |---------- n6
 *             |           |           |
 * n1 -------\ |           |           | /------- n7
 *            n4 ----------|---------- n5
 * n2 -------/ |           |           | \------- n8
 *             |           |           |
 * n3 ---------|           |           |---------- n9
 *
 *
 * BulkSend clients are placed on each left leaf node. Each right leaf node
 * is a packet sink for a left leaf node.  As a packet travels from one
 * logical processor to another (the link between n4 and n5), MPI messages
 * are passed containing the serialized packet. The message is then
 * deserialized into a new packet and sent on as normal.
 *
 * One packet is sent from each left leaf node. The packet sinks on the
 * right leaf nodes output logging information when they receive the packet.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/network-module.h"
#include "ns3/nix-vector-helper.h"
#include "ns3/on-off-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/point-to-point-helper.h"

#include <iomanip>
#include <map>
#include <string>
#include <vector>

using namespace ns3;
// Maps from a string-format stage to a NodeContainer filled with nodes.
// e.g., 'aggr': {AggregationBlock1}; 'tor': {tor1, tor2, ...}
using StageNodeMap = std::map<std::string, NodeContainer>;
// Maps from a string-format stage (with up/down facing) to a NetDeviceContainer
// filled with devices. e.g., 'tor-up': {dev1, dev2, ...}
using StageDeviceMap = std::map<std::string, NetDeviceContainer>;
// Maps from a string-format stage (with up/down facing) to an
// Ipv4InterfaceContainer filled with interfaces.
// e.g., 'tor-up': {if1, if2, ...}
using StageInterfaceMap = std::map<std::string, Ipv4InterfaceContainer>;

NS_LOG_COMPONENT_DEFINE("SpinefreeF2");

// Callback function to compute flow completion time.
void calcFCT(const Time &start, const Time &end) {
  NS_LOG_INFO("FCT " << (end - start).ToInteger(Time::NS) << " nsec.");
}

int main(int argc, char *argv[]) {
  // Fabric spec.
  // Fabric name.
  std::string NET = "f2";
  // Number of clusters.
  int NUM_CLUSTER = 1;
  // Number of ToR switches.
  int NUM_TOR = 32;
  // The FQDNs of devices which should enable pcap trace on.
  std::vector<std::string> pcap_fqdn{"f2-c1-t1-p1", "f2-c1-t32-p1",
                                     "f2-c1-ab1-p2", "f2-c1-ab1-p64"};

  bool tracing = false;
  bool verbose = false;
  uint32_t maxBytes = 10000;

  // Parse command line
  CommandLine cmd(__FILE__);
  cmd.AddValue("tracing", "Enable pcap tracing", tracing);
  cmd.AddValue("verbose", "verbose output", verbose);
  cmd.AddValue("maxBytes", "Total number of bytes for application to send",
               maxBytes);
  cmd.Parse(argc, argv);

  // Overrides default TCP MSS from 536B to 1448B to match Ethernet.
  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1448));
  GlobalValue::Bind("ChecksumEnabled", BooleanValue(false));

  Time::SetResolution(Time::NS);
  LogComponentEnable("SpinefreeF2",
                     (LogLevel)(LOG_LEVEL_INFO | LOG_PREFIX_TIME));

  if (verbose) {
    LogComponentEnable(
        "PacketSink",
        (LogLevel)(LOG_LEVEL_INFO | LOG_PREFIX_NODE | LOG_PREFIX_TIME));
  }

  NS_LOG_INFO("Create topology.");
  std::map<std::string, Ptr<Node>> globalNodeMap;
  std::map<std::string, Ptr<NetDevice>> globalDeviceMap;
  std::map<std::string, std::pair<Ptr<Ipv4>, uint32_t>> globalInterfaceMap;
  // All the nodes grouped by clusters.
  std::vector<StageNodeMap> cluster_nodes(NUM_CLUSTER);
  // All the devices grouped by clusters.
  std::vector<StageDeviceMap> cluster_devices(NUM_CLUSTER);
  // All the interfaces grouped by clusters.
  std::vector<StageInterfaceMap> cluster_ifs(NUM_CLUSTER);

  // Iterates over each cluster, adds aggregation block and ToR nodes and tracks
  // them separately using their FQDNs.
  for (int i = 0; i < NUM_CLUSTER; ++i) {
    // Creates aggregation block. Assuming only 1 AggrBlock in each cluster.
    std::string aggr_name = NET + "-c" + std::to_string(i + 1) + "-ab1";
    // Node is created with system id = cluster id.
    Ptr<Node> aggr = CreateObject<Node>(i);
    cluster_nodes[i]["aggr"].Add(aggr);
    globalNodeMap[aggr_name] = aggr;

    // Creates ToR switches and connects them to AggrBlock.
    // Intra-cluster links all have the same speed and latency.
    PointToPointHelper intraClusterLink;
    intraClusterLink.SetDeviceAttribute("DataRate", StringValue("10Gbps"));
    intraClusterLink.SetChannelAttribute("Delay", StringValue("20us"));
    for (int idx = 0; idx < NUM_TOR; ++idx) {
      std::string tor_name =
          NET + "-c" + std::to_string(i + 1) + "-t" + std::to_string(idx + 1);
      // Node is created with system id = cluster id.
      Ptr<Node> tor = CreateObject<Node>(i);
      cluster_nodes[i]["tor"].Add(tor);
      globalNodeMap[tor_name] = tor;
      // Establishes AggrBlock-ToR connectivity.
      NetDeviceContainer link = intraClusterLink.Install(tor, aggr);
      Ptr<NetDevice> tor_port = link.Get(0);
      Ptr<NetDevice> aggr_port = link.Get(1);
      std::string tor_dev_name = tor_name + "-p1";
      std::string aggr_dev_name =
          aggr_name + "-p" + std::to_string((idx + 1) * 2);
      cluster_devices[i]["tor-up"].Add(tor_port);
      cluster_devices[i]["aggr-down"].Add(aggr_port);
      globalDeviceMap[tor_dev_name] = tor_port;
      globalDeviceMap[aggr_dev_name] = aggr_port;
    }

    // Whether to enable pcap trace on ports specified in `pcap_fqdn`.
    if (tracing) {
      for (auto &&fqdn : pcap_fqdn) {
        intraClusterLink.EnablePcap(
            "intra-cluster", NetDeviceContainer(globalDeviceMap[fqdn]), true);
      }
    }
  }
  NS_LOG_INFO(globalNodeMap.size() << " nodes created in total.");

  // Sets up the network stacks and routing.
  InternetStackHelper stack;
  Ipv4NixVectorHelper nixRouting;
  stack.SetRoutingHelper(nixRouting); // has effect on the next Install ()
  stack.InstallAll();
  // Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  // Assigns IP addresses to each interface.
  for (int i = 0; i < NUM_CLUSTER; ++i) {
    // Intra-cluster interfaces are assigned base address 10.{cluster id}.1.0
    Ipv4AddressHelper intraClusterAddress;
    std::string intraBaseIP = "10." + std::to_string(i + 1) + ".1.0";
    // ToR up-facing interfaces are assigned address 10.{cluster id}.1.{tor id}
    intraClusterAddress.SetBase(intraBaseIP.c_str(), "255.255.255.0");
    Ipv4InterfaceContainer torUpIfs =
        intraClusterAddress.Assign(cluster_devices[i]["tor-up"]);
    cluster_ifs[i]["tor-up"].Add(torUpIfs);
    // AggrBlock down-facing interfaces are assigned address
    // 10.{cluster id}.1.{100 + tor id}
    intraClusterAddress.SetBase(intraBaseIP.c_str(), "255.255.255.0",
                                "0.0.0.101");
    Ipv4InterfaceContainer aggrDownIfs =
        intraClusterAddress.Assign(cluster_devices[i]["aggr-down"]);
    cluster_ifs[i]["aggr-down"].Add(aggrDownIfs);
    // Establishes global interface map.
    for (int idx = 0; idx < NUM_TOR; ++idx) {
      std::string tor_if_name = NET + "-c" + std::to_string(i + 1) + "-t" +
                                std::to_string(idx + 1) + "-p1";
      std::string aggr_if_name = NET + "-c" + std::to_string(i + 1) + "-ab1" +
                                 "-p" + std::to_string((idx + 1) * 2);
      globalInterfaceMap[tor_if_name] = torUpIfs.Get(idx);
      globalInterfaceMap[aggr_if_name] = aggrDownIfs.Get(idx);
    }
  }

  // Creates a packet sink on the last ToR of cluster 1.
  std::string srcTor = "f2-c1-t1";
  std::string dstTor = "f2-c1-t32";
  uint16_t port = 50000;
  PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));
  ApplicationContainer sinkApps;
  sinkApps.Add(sinkHelper.Install(globalNodeMap[dstTor]));
  sinkApps.Start(Seconds(0.0));

  // Creates the BulkSend applications to send
  ApplicationContainer clientApps;
  Ipv4Address dstAddr =
      globalInterfaceMap[dstTor + "-p1"]
          .first->GetAddress(globalInterfaceMap[dstTor + "-p1"].second, 0)
          .GetLocal();
  BulkSendHelper clientHelper("ns3::TcpSocketFactory",
                              InetSocketAddress(dstAddr, port));
  // Set the amount of data to send in bytes.  Zero is unlimited.
  clientHelper.SetAttribute("MaxBytes", UintegerValue(maxBytes));
  clientApps.Add(clientHelper.Install(globalNodeMap[srcTor]));
  for (uint32_t i = 0; i < clientApps.GetN(); ++i) {
    clientApps.Get(i)->TraceConnectWithoutContext("Fct",
                                                  MakeCallback(&calcFCT));
  }
  clientApps.Start(Seconds(1.0));

  // Flow monitor. Only install FlowMonitor if verbose is true.
  Ptr<FlowMonitor> flowMonitor;
  FlowMonitorHelper flowHelper;
  if (verbose) {
    flowMonitor = flowHelper.InstallAll();
  }

  NS_LOG_INFO("Run simulation.");
  Simulator::Stop(Seconds(10));
  Simulator::Run();
  NS_LOG_INFO("Simulation done.");

  // Dump flow stats.
  if (verbose) {
    flowMonitor->SerializeToXmlFile("SpinefreeF2.xml", true, true);
  }
  Simulator::Destroy();

  return 0;
}
