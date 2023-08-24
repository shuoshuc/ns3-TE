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
 * This script creates a spine-free data center topology. The fabric consists of
 * 33 clusters. Inside each cluster, the switches are connected as a folded Clos
 * topology between ToRs and the aggregation block.
 *
 * PacketSinks are placed on each ToR node. Given an input traffic trace,
 * corresponding nodes are initialized with BulkSend applications to send flows
 * to the sinks.
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

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <istream>
#include <map>
#include <numeric>
#include <queue>
#include <set>
#include <string>
#include <tuple>
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
// TM row format: <src, dst, demand, start_time>.
using TMRow = std::tuple<std::string, std::string, uint64_t, uint64_t>;
// Complete traffic matrix (not in actual matrix format).
using TrafficMatrix = std::vector<TMRow>;

NS_LOG_COMPONENT_DEFINE("SpinefreeF2");

// The csv file parsing apparatus.
std::vector<std::string> readCSVRow(const std::string &row) {
  // Skips empty line or comment line that starts with a hashtag.
  if (row.size() <= 0 || row[0] == '#') {
    return {};
  }

  std::vector<std::string> fields{""};
  size_t i = 0; // index of the current field
  for (char c : row) {
    switch (c) {
    case ',': // end of field
      fields.push_back("");
      i++;
      break;
    default:
      fields[i].push_back(c);
      break;
    }
  }
  return fields;
}

TrafficMatrix readCSV(const std::string &filename) {
  std::ifstream tm_file(filename);
  TrafficMatrix tm;
  std::string row;
  while (std::getline(tm_file, row)) {
    std::vector<std::string> parsed_row = readCSVRow(row);
    if (parsed_row.empty()) {
      continue;
    }
    if (parsed_row.size() != 4) {
      NS_LOG_ERROR("Error parsing TM row: " << row);
      continue;
    }
    tm.push_back({parsed_row[0], parsed_row[1], std::stol(parsed_row[2]),
                  std::stol(parsed_row[3])});
  }
  return tm;
}

// Looks up the corresponding generation for a given cluster index. The second
// parameter is a vector of number of clusters for each generation. For example,
// [11, 11, 11] means 11 cluster for Gen 1/2/3, respectively.
int getClusterGenByIndex(int idx, std::vector<int> genVec) {
  if (idx < 1 || idx > std::accumulate(genVec.begin(), genVec.end(), 0)) {
    NS_LOG_ERROR("Invalid cluster index " << idx);
    return -1;
  }
  int partial_sum = 0;
  for (uint32_t it = 0; it < genVec.size(); ++it) {
    partial_sum += genVec[it];
    if (idx <= partial_sum) {
      return it + 1;
    }
  }
  // It will be an error if the function ends up returning here.
  return -1;
}

// Callback function to compute flow completion time.
void calcFCT(const Time &start, const Time &end) {
  NS_LOG_INFO("FCT " << (end - start).ToInteger(Time::NS) << " nsec.");
}

int main(int argc, char *argv[]) {

  // ===========================
  // ==                       ==
  // == Fabric spec and flags ==
  // ==                       ==
  // ===========================

  // Fabric name.
  std::string NET = "f2";
  // Number of Gen. 1/2/3 clusters.
  std::vector<int> GEN_VEC{11, 11, 11};
  // Number of clusters.
  int NUM_CLUSTER = std::accumulate(GEN_VEC.begin(), GEN_VEC.end(), 0);
  // Number of ToR switches.
  int NUM_TOR = 32;
  // Number of ports on an AggrBlock.
  int NUM_AGGR_PORTS = 64;
  // Cluster speed map from Gen. ID to speed in Gbps.
  std::map<int, int> SPEED_MAP{{1, 40}, {2, 100}, {3, 200}};
  // The FQDNs of intra-cluster devices which should enable pcap trace on.
  // All device names are stored as a map:
  // cluster id: {"f2-c1-t1-p1", "f2-c2-ab1-p1", ...}
  std::map<int, std::set<std::string>> pcap_intra_fqdn{
      {1, {"f2-c1-t1-p1", "f2-c1-t2-p1", "f2-c1-t32-p1"}},
      {33, {"f2-c33-t32-p1"}}};
  // The FQDNs of inter-cluster devices which should enable pcap trace on.
  // All device names are stored as a map like `pcap_intra_fqdn`.
  std::map<int, std::set<std::string>> pcap_inter_fqdn{{1, {"f2-c1-ab1-p63"}},
                                                       {33, {"f2-c33-ab1-p1"}}};
  std::string MSFT_WEB_TRACE = "./trace/f2-msft-web.csv";

  bool tracing = false;
  bool verbose = false;
  std::string trafficInput = "./trace/test.csv";
  // Parse command line
  CommandLine cmd(__FILE__);
  cmd.AddValue("tracing", "Enable pcap tracing", tracing);
  cmd.AddValue("verbose", "verbose output", verbose);
  cmd.AddValue("trafficInput", "File path of the input traffic demand file",
               trafficInput);
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

  // =====================
  // ==                 ==
  // == Create topology ==
  // ==                 ==
  // =====================
  NS_LOG_INFO("Create topology.");
  std::map<std::string, Ptr<Node>> globalNodeMap;
  std::map<std::string, Ptr<NetDevice>> globalDeviceMap;
  std::map<std::string, std::pair<Ptr<Ipv4>, uint32_t>> globalInterfaceMap;
  // This map maintains the AggrBlock port peering information. For each bi-di
  // link, the records exist in the map, e.g.,
  // f2-c1-ab1-p1: f2-c2-ab1-p1
  // f2-c2-ab1-p1: f2-c1-ab1-p1
  std::map<std::string, std::string> globalPeerMap;
  // All the nodes grouped by clusters.
  std::vector<StageNodeMap> cluster_nodes(NUM_CLUSTER);
  // All the devices grouped by clusters.
  std::vector<StageDeviceMap> cluster_devices(NUM_CLUSTER);
  // All the interfaces grouped by clusters.
  std::vector<StageInterfaceMap> cluster_ifs(NUM_CLUSTER);
  // The available DCN port index grouped by clusters.
  std::vector<std::queue<int>> cluster_dcn_ports(NUM_CLUSTER);

  // Iterates over each cluster, adds aggregation block and ToR nodes and tracks
  // them separately using their FQDNs.
  for (int i = 0; i < NUM_CLUSTER; ++i) {
    // Creates aggregation block. Assuming only 1 AggrBlock in each cluster.
    std::string aggr_name = NET + "-c" + std::to_string(i + 1) + "-ab1";
    // Node is created with system id = cluster id.
    Ptr<Node> aggr = CreateObject<Node>(i);
    cluster_nodes[i]["aggr"].Add(aggr);
    globalNodeMap[aggr_name] = aggr;
    for (int p = 1; p <= NUM_AGGR_PORTS; p += 2) {
      cluster_dcn_ports[i].push(p);
    }

    // Creates ToR switches and connects them to AggrBlock.
    // Intra-cluster links all have the same speed and latency.
    PointToPointHelper intraClusterLink;
    int gen_id = getClusterGenByIndex(i + 1, GEN_VEC);
    // Invalid generation id, abort.
    if (gen_id < 0) {
      NS_LOG_ERROR("Invalid cluster index. Gen id " << gen_id);
      return -1;
    }
    intraClusterLink.SetDeviceAttribute(
        "DataRate", StringValue(std::to_string(SPEED_MAP[gen_id]) + "Gbps"));
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

    // Whether to enable pcap trace on ports specified in `pcap_intra_fqdn`.
    if (tracing && pcap_intra_fqdn.count(i + 1)) {
      for (auto &&fqdn : pcap_intra_fqdn[i + 1]) {
        if (!globalDeviceMap.count(fqdn)) {
          NS_LOG_ERROR(fqdn << " not found in globalDeviceMap!");
          continue;
        }
        intraClusterLink.EnablePcap(fqdn + ".pcap", globalDeviceMap[fqdn], true,
                                    true);
      }
    }
  }

  // Now that all clusters are constructed, inter-connects them as a full mesh.
  for (int i = 0; i < NUM_CLUSTER; ++i) {
    std::string aggr_name = NET + "-c" + std::to_string(i + 1) + "-ab1";
    Ptr<Node> aggr_sw = globalNodeMap[aggr_name];
    for (int j = i + 1; j < NUM_CLUSTER; ++j) {
      std::string peer_aggr_name = NET + "-c" + std::to_string(j + 1) + "-ab1";
      Ptr<Node> peer_aggr_sw = globalNodeMap[peer_aggr_name];

      // Inter-cluster links may not have the same speed, actual speed is
      // determined by auto-negotiation.
      PointToPointHelper interClusterLink;
      // Performs speed auto negotiation.
      int self_gen_id = getClusterGenByIndex(i + 1, GEN_VEC);
      int peer_gen_id = getClusterGenByIndex(j + 1, GEN_VEC);
      // Invalid generation id, abort.
      if (self_gen_id < 0 || peer_gen_id < 0) {
        NS_LOG_ERROR("Invalid cluster index. Self gen id "
                     << self_gen_id << ", peer gen id " << peer_gen_id);
        return -1;
      }
      interClusterLink.SetDeviceAttribute(
          "DataRate",
          StringValue(std::to_string(std::min(SPEED_MAP[self_gen_id],
                                              SPEED_MAP[peer_gen_id])) +
                      "Gbps"));
      interClusterLink.SetChannelAttribute("Delay", StringValue("20us"));

      NetDeviceContainer link = interClusterLink.Install(aggr_sw, peer_aggr_sw);
      Ptr<NetDevice> self_port = link.Get(0);
      Ptr<NetDevice> peer_port = link.Get(1);
      std::string self_port_name =
          aggr_name + "-p" + std::to_string(cluster_dcn_ports[i].front());
      cluster_dcn_ports[i].pop();
      std::string peer_port_name =
          peer_aggr_name + "-p" + std::to_string(cluster_dcn_ports[j].front());
      cluster_dcn_ports[j].pop();
      cluster_devices[i]["aggr-up"].Add(self_port);
      cluster_devices[j]["aggr-up"].Add(peer_port);
      globalDeviceMap[self_port_name] = self_port;
      globalDeviceMap[peer_port_name] = peer_port;
      globalPeerMap[self_port_name] = peer_port_name;
      globalPeerMap[peer_port_name] = self_port_name;

      // Whether to enable pcap trace on ports specified in `pcap_inter_fqdn`.
      if (tracing) {
        if (pcap_inter_fqdn.count(i + 1) &&
            pcap_inter_fqdn[i + 1].count(self_port_name)) {
          interClusterLink.EnablePcap(self_port_name + ".pcap", self_port, true,
                                      true);
        }
        if (pcap_inter_fqdn.count(j + 1) &&
            pcap_inter_fqdn[j + 1].count(peer_port_name)) {
          interClusterLink.EnablePcap(peer_port_name + ".pcap", peer_port, true,
                                      true);
        }
      }
    }
  }
  NS_LOG_INFO(globalNodeMap.size() << " nodes created in total.");

  // =======================
  // ==                   ==
  // == Configure routing ==
  // ==                   ==
  // =======================

  NS_LOG_INFO("Configure routing.");
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
      std::string aggr_if_name = NET + "-c" + std::to_string(i + 1) + "-ab1-p" +
                                 std::to_string((idx + 1) * 2);
      globalInterfaceMap[tor_if_name] = torUpIfs.Get(idx);
      globalInterfaceMap[aggr_if_name] = aggrDownIfs.Get(idx);
    }
    // Inter-cluster interfaces are assigned IP address:
    // 10.100.{cluster id}.{port id / 2 + 1}
    Ipv4AddressHelper dcnAddress;
    std::string startIP = "0.0." + std::to_string(i + 1) + ".1";
    dcnAddress.SetBase("10.100.0.0", "255.255.0.0", startIP.c_str());
    Ipv4InterfaceContainer dcnIfs =
        dcnAddress.Assign(cluster_devices[i]["aggr-up"]);
    cluster_ifs[i]["aggr-up"].Add(dcnIfs);
    // Establishes global interface map.
    for (int p = 0; p < NUM_AGGR_PORTS / 2; ++p) {
      std::string dcn_if_name = NET + "-c" + std::to_string(i + 1) + "-ab1-p" +
                                std::to_string(p * 2 + 1);
      globalInterfaceMap[dcn_if_name] = dcnIfs.Get(p);
    }
  }

  // ======================
  // ==                  ==
  // == Generate traffic ==
  // ==                  ==
  // ======================

  NS_LOG_INFO("Generate traffic.");

  // Load in the TM file.
  TrafficMatrix TM = readCSV(trafficInput);
  NS_LOG_INFO("Trace entries: " << TM.size());

  // Creates a packet sink on all ToRs.
  uint16_t port = 50000;
  PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));
  ApplicationContainer sinkApps;
  for (int i = 0; i < NUM_CLUSTER; ++i) {
    sinkApps.Add(sinkHelper.Install(cluster_nodes[i]["tor"]));
  }
  sinkApps.Start(Seconds(0.0));

  // Creates the BulkSend applications to send. Who sends to who, how much and
  // when to send is determined by the rows in TM.
  ApplicationContainer clientApps;
  for (const TMRow &row : TM) {
    std::string src = std::get<0>(row);
    std::string dst = std::get<1>(row);
    uint64_t flow_size = std::get<2>(row);
    uint64_t start_time = std::get<3>(row);
    Ipv4Address dstAddr =
        globalInterfaceMap[dst + "-p1"]
            .first->GetAddress(globalInterfaceMap[dst + "-p1"].second, 0)
            .GetLocal();
    BulkSendHelper clientHelper("ns3::TcpSocketFactory",
                                InetSocketAddress(dstAddr, port));
    // Set the amount of data to send in bytes.  Zero is unlimited.
    clientHelper.SetAttribute("MaxBytes", UintegerValue(flow_size));
    ApplicationContainer client = clientHelper.Install(globalNodeMap[src]);
    // Register callback to measure FCT, there is supposed to be only one app
    // in this container.
    client.Get(0)->TraceConnectWithoutContext("Fct", MakeCallback(&calcFCT));
    client.Start(NanoSeconds(start_time));
    clientApps.Add(client);
  }

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
