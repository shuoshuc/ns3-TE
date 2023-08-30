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
 *
 */


/*
 * Network topology:
 *
 *                         n2
 *                        ^  \
 *                       /    \
 *                      /      \
 *                     /        v
 *       n0 --------> n1         n4 ------> n5
 *                     \        ^
 *                      \      /
 *                       \    /
 *                        v  /
 *                         n3
 */


#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"

#include <cassert>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ECMPDemo");

int main(int argc, char *argv[]) {
  Time::SetResolution(Time::NS);
  LogComponentEnable("ECMPDemo", (LogLevel)(LOG_LEVEL_INFO | LOG_PREFIX_TIME));

  // Users may find it convenient to turn on explicit debugging
  // for selected modules; the below lines suggest how to do this
#if 0
  LogComponentEnable ("ECMPDemo", LOG_LEVEL_INFO);
#endif

  // Set up some default values for the simulation.  Use the
  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1448));
  Config::SetDefault("ns3::Ipv4StaticRouting::FlowEcmpRouting",
                     BooleanValue(true));

  // DefaultValue::Bind ("DropTailQueue::m_maxPackets", 30);

  // Allow the user to override any of the defaults and the above
  // DefaultValue::Bind ()s at run-time, via command-line arguments
  CommandLine cmd(__FILE__);
  bool enableFlowMonitor = false;
  cmd.AddValue("EnableMonitor", "Enable Flow Monitor", enableFlowMonitor);
  cmd.Parse(argc, argv);

  // Here, we will explicitly create four nodes.  In more sophisticated
  // topologies, we could configure a node factory.
  NS_LOG_INFO("Create nodes.");
  NodeContainer c;
  c.Create(6);
  NodeContainer n0n1 = NodeContainer(c.Get(0), c.Get(1));
  NodeContainer n1n2 = NodeContainer(c.Get(1), c.Get(2));
  NodeContainer n1n3 = NodeContainer(c.Get(1), c.Get(3));
  NodeContainer n2n4 = NodeContainer(c.Get(2), c.Get(4));
  NodeContainer n3n4 = NodeContainer(c.Get(3), c.Get(4));
  NodeContainer n4n5 = NodeContainer(c.Get(4), c.Get(5));

  // We create the channels first without any IP addressing information
  NS_LOG_INFO("Create channels.");
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));
  NetDeviceContainer d0d1 = p2p.Install(n0n1);
  NetDeviceContainer d1d2 = p2p.Install(n1n2);
  NetDeviceContainer d1d3 = p2p.Install(n1n3);
  NetDeviceContainer d2d4 = p2p.Install(n2n4);
  NetDeviceContainer d3d4 = p2p.Install(n3n4);
  NetDeviceContainer d4d5 = p2p.Install(n4n5);

  InternetStackHelper internet;
  internet.InstallAll();

  // Later, we add IP addresses.
  NS_LOG_INFO("Assign IP Addresses.");
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i0i1 = ipv4.Assign(d0d1);
  ipv4.SetBase("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer i1i2 = ipv4.Assign(d1d2);
  Ipv4InterfaceContainer i1i3 = ipv4.Assign(d1d3);
  ipv4.SetBase("10.1.3.0", "255.255.255.0");
  Ipv4InterfaceContainer i2i4 = ipv4.Assign(d2d4);
  Ipv4InterfaceContainer i3i4 = ipv4.Assign(d3d4);
  ipv4.SetBase("10.1.4.0", "255.255.255.0");
  Ipv4InterfaceContainer i4i5 = ipv4.Assign(d4d5);

  // Create router nodes, initialize routing database and set up the routing
  // tables in the nodes.
  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  for (uint32_t i = 0; i < c.GetN(); ++i) {
    Ptr<Node> sw = c.Get(i);
    // First removes all routes.
    Ptr<Ipv4StaticRouting> staticRouting =
        ipv4RoutingHelper.GetStaticRouting(sw->GetObject<Ipv4>());
    while (staticRouting->GetNRoutes()) {
      staticRouting->RemoveRoute(0);
    }
    // Adds localhost and default routes. Only n0 and n5 need default route.
    staticRouting->AddNetworkRouteTo(Ipv4Address("127.0.0.0"), Ipv4Mask("/8"),
                                     0);
    if (i == 0 || i == 5) {
      staticRouting->AddNetworkRouteTo(Ipv4Address("0.0.0.0"), Ipv4Mask("/0"),
                                       1);
    }
    if (i == 2 || i == 3) {
      staticRouting->AddNetworkRouteTo(Ipv4Address("10.1.1.0"), Ipv4Mask("/24"),
                                       1);
      staticRouting->AddNetworkRouteTo(Ipv4Address("10.1.4.0"), Ipv4Mask("/24"),
                                       2);
    }
    if (i == 1) {
      staticRouting->AddNetworkRouteTo(Ipv4Address("10.1.1.0"), Ipv4Mask("/24"),
                                       1);
      std::map<int, int> weights{{2, 3}, {3, 1000}};
      std::vector<int> group;
      for (const auto& [interface, weight] : weights) {
        std::vector<int> vec(weight, interface);
        group.insert(std::end(group), std::begin(vec), std::end(vec));
      }
      staticRouting->AddNetworkRouteTo(Ipv4Address("10.1.4.0"), Ipv4Mask("/24"),
                                       2, group);
    }
    if (i == 4) {
      staticRouting->AddNetworkRouteTo(Ipv4Address("10.1.1.0"), Ipv4Mask("/24"),
                                       1);
      staticRouting->AddNetworkRouteTo(Ipv4Address("10.1.1.0"), Ipv4Mask("/24"),
                                       2);
      staticRouting->AddNetworkRouteTo(Ipv4Address("10.1.4.0"), Ipv4Mask("/24"),
                                       3);
    }
  }

  // Create the BulkSend application.
  NS_LOG_INFO("Create Applications.");
  uint16_t port = 9; // Discard port (RFC 863)
  ApplicationContainer apps;
  for (int i = 0; i < 10; ++i) {
    BulkSendHelper bulk("ns3::TcpSocketFactory",
                        InetSocketAddress(i4i5.GetAddress(1), port));
    bulk.SetAttribute("MaxBytes", UintegerValue(1000));
    apps = bulk.Install(c.Get(0));
    apps.Start(Seconds(1.0));
    apps.Stop(Seconds(10.0));
  }

  // Create a packet sink to receive these packets
  PacketSinkHelper sink("ns3::TcpSocketFactory",
                        InetSocketAddress(Ipv4Address::GetAny(), port));
  apps = sink.Install(c.Get(5));
  apps.Start(Seconds(0.0));
  apps.Stop(Seconds(10.0));

  p2p.EnablePcapAll("routing");

  // Flow Monitor
  FlowMonitorHelper flowmonHelper;
  if (enableFlowMonitor) {
    flowmonHelper.InstallAll();
  }

  Ipv4GlobalRoutingHelper g;
  g.PrintRoutingTableAt(
      Seconds(0), c.Get(1),
      Create<OutputStreamWrapper>("n1.routes", std::ios::out));

  NS_LOG_INFO("Run Simulation.");
  Simulator::Stop(Seconds(11));
  Simulator::Run();
  NS_LOG_INFO("Done.");

  if (enableFlowMonitor) {
    flowmonHelper.SerializeToXmlFile("ecmp-demo.flowmon", false, false);
  }

  Simulator::Destroy();
  return 0;
}
