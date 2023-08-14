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
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/network-module.h"
#include "ns3/nix-vector-helper.h"
#include "ns3/on-off-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/point-to-point-helper.h"

#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("Demo1Proc");

int
main(int argc, char* argv[])
{
    bool nix = true;
    bool tracing = false;
    bool verbose = false;
    uint32_t maxBytes = 10000;
    uint32_t npairs = 2;

    // Parse command line
    CommandLine cmd(__FILE__);
    cmd.AddValue("nix", "Enable the use of nix-vector or global routing", nix);
    cmd.AddValue("tracing", "Enable pcap tracing", tracing);
    cmd.AddValue("verbose", "verbose output", verbose);
    cmd.AddValue("maxBytes", "Total number of bytes for application to send", maxBytes);
    cmd.AddValue("npairs", "Number of node pairs", npairs);
    cmd.Parse(argc, argv);

    Time::SetResolution(Time::NS);
    LogComponentEnable("Demo1Proc", (LogLevel)(LOG_LEVEL_INFO | LOG_PREFIX_TIME));

    if (verbose)
    {
        LogComponentEnable("PacketSink",
                           (LogLevel)(LOG_LEVEL_INFO | LOG_PREFIX_NODE | LOG_PREFIX_TIME));
    }

    // Create leaf nodes on left with system id 0
    NodeContainer leftLeafNodes;
    leftLeafNodes.Create(npairs, 0);

    // Create router nodes.  Left router
    // with system id 0, right router with
    // system id 1
    NodeContainer routerNodes;
    Ptr<Node> routerNode1 = CreateObject<Node>(0);
    Ptr<Node> routerNode2 = CreateObject<Node>(1);
    routerNodes.Add(routerNode1);
    routerNodes.Add(routerNode2);

    // Create leaf nodes on right with system id 1
    NodeContainer rightLeafNodes;
    rightLeafNodes.Create(npairs, 1);

    PointToPointHelper routerLink;
    routerLink.SetDeviceAttribute("DataRate", StringValue("10Gbps"));
    routerLink.SetChannelAttribute("Delay", StringValue("20us"));

    PointToPointHelper leafLink;
    leafLink.SetDeviceAttribute("DataRate", StringValue("10Gbps"));
    leafLink.SetChannelAttribute("Delay", StringValue("20us"));

    // Add link connecting routers
    NetDeviceContainer routerDevices;
    routerDevices = routerLink.Install(routerNodes);

    // Add links for left side leaf nodes to left router
    NetDeviceContainer leftRouterDevices;
    NetDeviceContainer leftLeafDevices;
    for (uint32_t i = 0; i < npairs; ++i)
    {
        NetDeviceContainer temp = leafLink.Install(leftLeafNodes.Get(i), routerNodes.Get(0));
        leftLeafDevices.Add(temp.Get(0));
        leftRouterDevices.Add(temp.Get(1));
    }

    // Add links for right side leaf nodes to right router
    NetDeviceContainer rightRouterDevices;
    NetDeviceContainer rightLeafDevices;
    for (uint32_t i = 0; i < npairs; ++i)
    {
        NetDeviceContainer temp = leafLink.Install(rightLeafNodes.Get(i), routerNodes.Get(1));
        rightLeafDevices.Add(temp.Get(0));
        rightRouterDevices.Add(temp.Get(1));
    }

    InternetStackHelper stack;
    if (nix)
    {
        Ipv4NixVectorHelper nixRouting;
        stack.SetRoutingHelper(nixRouting); // has effect on the next Install ()
    }

    stack.InstallAll();

    Ipv4InterfaceContainer routerInterfaces;
    Ipv4InterfaceContainer leftLeafInterfaces;
    Ipv4InterfaceContainer leftRouterInterfaces;
    Ipv4InterfaceContainer rightLeafInterfaces;
    Ipv4InterfaceContainer rightRouterInterfaces;

    Ipv4AddressHelper leftAddress;
    leftAddress.SetBase("10.1.1.0", "255.255.255.0");

    Ipv4AddressHelper routerAddress;
    routerAddress.SetBase("10.2.1.0", "255.255.255.0");

    Ipv4AddressHelper rightAddress;
    rightAddress.SetBase("10.3.1.0", "255.255.255.0");

    // Router-to-Router interfaces
    routerInterfaces = routerAddress.Assign(routerDevices);

    // Left interfaces
    for (uint32_t i = 0; i < npairs; ++i)
    {
        NetDeviceContainer ndc;
        ndc.Add(leftLeafDevices.Get(i));
        ndc.Add(leftRouterDevices.Get(i));
        Ipv4InterfaceContainer ifc = leftAddress.Assign(ndc);
        leftLeafInterfaces.Add(ifc.Get(0));
        leftRouterInterfaces.Add(ifc.Get(1));
        leftAddress.NewNetwork();
    }

    // Right interfaces
    for (uint32_t i = 0; i < npairs; ++i)
    {
        NetDeviceContainer ndc;
        ndc.Add(rightLeafDevices.Get(i));
        ndc.Add(rightRouterDevices.Get(i));
        Ipv4InterfaceContainer ifc = rightAddress.Assign(ndc);
        rightLeafInterfaces.Add(ifc.Get(0));
        rightRouterInterfaces.Add(ifc.Get(1));
        rightAddress.NewNetwork();
    }

    if (!nix)
    {
        Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    }

    if (tracing)
    {
        routerLink.EnablePcap("router", routerDevices, true);
        leafLink.EnablePcap("leaf-left", leftLeafDevices, true);
        leafLink.EnablePcap("leaf-right", rightLeafDevices, true);
    }

    // Create a packet sink on the right leafs to receive packets from left leafs

    uint16_t port = 50000;
    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(),
                                                  port));
    ApplicationContainer sinkApps;
    for (uint32_t i = 0; i < npairs; ++i)
    {
        sinkApps.Add(sinkHelper.Install(rightLeafNodes.Get(i)));
    }
    sinkApps.Start(Seconds(0.0));

    // Create the BulkSend applications to send
    ApplicationContainer clientApps;
    for (uint32_t i = 0; i < npairs; ++i)
    {
        BulkSendHelper clientHelper("ns3::TcpSocketFactory",
                                    InetSocketAddress(rightLeafInterfaces.GetAddress(i), port));
        // Set the amount of data to send in bytes.  Zero is unlimited.
        clientHelper.SetAttribute("MaxBytes", UintegerValue(maxBytes));
        clientApps.Add(clientHelper.Install(leftLeafNodes.Get(i)));
    }
    clientApps.Start(Seconds(1.0));

    NS_LOG_INFO("Run Simulation.");
    Simulator::Stop(Seconds(10));
    Simulator::Run();
    NS_LOG_INFO("Done.");
    Simulator::Destroy();

    return 0;
}
