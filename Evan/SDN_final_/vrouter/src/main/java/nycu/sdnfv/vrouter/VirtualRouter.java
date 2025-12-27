/*
 * Copyright 2025-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.sdnfv.vrouter;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
import static org.onlab.packet.ICMP6.NEIGHBOR_SOLICITATION;

import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;
import org.onosproject.net.EncapsulationType;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.onosproject.routeservice.ResolvedRoute;
import org.onosproject.routeservice.RouteInfo;
import org.onosproject.routeservice.RouteService;
import org.onosproject.routeservice.RouteTableId;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceEvent;
import org.onosproject.net.intf.InterfaceListener;
import org.onosproject.net.intf.InterfaceService;
import org.onlab.packet.ndp.NeighborAdvertisement;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.packet.IpAddress.Version;
import org.onosproject.net.intent.Intent;
import org.onosproject.net.intent.MultiPointToSinglePointIntent;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.intent.SinglePointToMultiPointIntent;
import org.onosproject.net.intent.IntentService;
import org.onlab.packet.ndp.NeighborDiscoveryOptions;
import org.onosproject.net.intent.Key;
import java.util.stream.Collectors;

import org.onlab.packet.*;
import org.onosproject.net.packet.*;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.List;

import java.lang.ProcessBuilder.Redirect.Type;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(immediate = true)
public class VirtualRouter {

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected RouteService routeService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final RouterConfigListener cfgListener = new RouterConfigListener();

    private final ConfigFactory<ApplicationId, RouterConfig> factory = new ConfigFactory<ApplicationId, RouterConfig>(
            APP_SUBJECT_FACTORY, RouterConfig.class, "router") {
        @Override
        public RouterConfig createConfig() {
            return new RouterConfig();
        }
    };

    private MacAddress vrouterMac;
    private MacAddress frrMac;

    private IpAddress vrouterGatewayIpv4;
    private IpAddress vrouterGatewayIpv6;

    private List<IpAddress> wanPortIp4;
    private List<IpAddress> wanPortIp6;
    private List<IpPrefix> v4Peer;
    private List<IpPrefix> v6Peer;

    private ConnectPoint frrCP;

    private ApplicationId appId;

    protected Map<IpAddress, MacAddress> arpTable = Maps.newConcurrentMap();

    protected Map<DeviceId, Map<MacAddress, PortNumber>> macTables = Maps.newConcurrentMap();

    private PacketProcessor arpProcessor = new ProxyArpProcessor();

    private LearningBridgeProcessor learningBridgeProcessor = new LearningBridgeProcessor();

    private VirtualRouterProcessor virtualRouterProcessor = new VirtualRouterProcessor();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nycu.sdnfv.vrouter");

        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId);

        if (arpProcessor != null)
            packetService.removeProcessor(arpProcessor);

        if (learningBridgeProcessor != null)
            packetService.removeProcessor(learningBridgeProcessor);

        if (virtualRouterProcessor != null)
            packetService.removeProcessor(virtualRouterProcessor);

        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);

        arpProcessor = null;
        learningBridgeProcessor = null;
        virtualRouterProcessor = null;

        intentService.getIntents()
                .forEach(intent -> {
                    if (intent.appId().equals(appId)) {
                        intentService.withdraw(intent);
                    }
                });

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    protected Key makeIntentKey(
            String tag,
            Set<FilteredConnectPoint> ingressCPs,
            FilteredConnectPoint egressCP,
            short ethType) {

        List<String> ingressList = ingressCPs.stream()
                .map(cp -> cp.connectPoint().deviceId() + "/" + cp.connectPoint().port())
                .sorted()
                .collect(Collectors.toList());

        String ingressPart = String.join(",", ingressList);

        String keyStr = String.format(
                "%s|0x%04x|IN[%s]|OUT[%s/%s]",
                tag,
                ethType & 0xFFFF,
                ingressPart,
                egressCP.connectPoint().deviceId(),
                egressCP.connectPoint().port()
        );
        return Key.of(keyStr, appId);
    }


    private class RouterConfigListener implements NetworkConfigListener {
        private boolean intentsInstalled = false;

        @Override
        public void event(NetworkConfigEvent event) {

            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
                    && event.configClass().equals(RouterConfig.class)) {
                RouterConfig config = cfgService.getConfig(appId, RouterConfig.class);

                if (config != null) {
                    frrMac = MacAddress.valueOf(config.frroutingMac());
                    frrCP = ConnectPoint.deviceConnectPoint(config.frroutingConnectPoint());
                    vrouterMac = MacAddress.valueOf(config.gatewayMac());
                    vrouterGatewayIpv4 = IpAddress.valueOf(config.gatewayIpv4());
                    vrouterGatewayIpv6 = IpAddress.valueOf(config.gatewayIpv6());
                    wanPortIp4 = config.wanPortIp4();
                    wanPortIp6 = config.wanPortIp6();
                    v4Peer = config.v4Peer();
                    v6Peer = config.v6Peer();

                    arpTable.put(vrouterGatewayIpv4, vrouterMac);
                    arpTable.put(vrouterGatewayIpv6, vrouterMac);

                    if (!intentsInstalled) {
                        installIngressIntent(frrCP, wanPortIp4, v4Peer, Ethernet.TYPE_IPV4);
                        installIngressIntent(frrCP, wanPortIp6, v6Peer, Ethernet.TYPE_IPV6);

                        installEgressIntent(frrCP, wanPortIp4, v4Peer, Ethernet.TYPE_IPV4);
                        installEgressIntent(frrCP, wanPortIp6, v6Peer, Ethernet.TYPE_IPV6);
                        intentsInstalled = true;
                    }

                    // vrouter goes first
                    packetService.addProcessor(virtualRouterProcessor, PacketProcessor.director(2));
                    packetService.addProcessor(arpProcessor, PacketProcessor.director(1));
                    packetService.addProcessor(learningBridgeProcessor, PacketProcessor.director(3));

                }

            }
        }

        private void installEgressIntent(ConnectPoint bgpSpeakerCP, List<IpAddress> wanIps, List<IpPrefix> peers,
                                         Short type) {
            Integer peerSize = peers.size();

            for (int i = 0; i < peerSize; i++) {
                ConnectPoint peerCP = interfaceService.getMatchingInterface(wanIps.get(i))
                        .connectPoint();

                IpPrefix peer = peers.get(i);

                TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
                selector.matchEthType(type);

                if (type == Ethernet.TYPE_IPV4)
                    selector.matchIPDst(peer);
                else if (type == Ethernet.TYPE_IPV6)
                    selector.matchIPv6Dst(peer);

                FilteredConnectPoint egressFilteredCP = new FilteredConnectPoint(peerCP);
                FilteredConnectPoint ingressFilteredCP = new FilteredConnectPoint(bgpSpeakerCP);

                PointToPointIntent.Builder intentBuilder = PointToPointIntent.builder()
                        .key(makeIntentKey("Egress", Sets.newHashSet(ingressFilteredCP), egressFilteredCP, type))
                        .appId(appId)
                        .filteredIngressPoint(ingressFilteredCP)
                        .filteredEgressPoint(egressFilteredCP)
                        .selector(selector.build())
                        .priority(30);

                log.info("Submitting type 0x{} egress intent", Integer.toHexString(type & 0xFFFF));
                intentService.submit(intentBuilder.build());

            }

        }

        private void installIngressIntent(ConnectPoint bgpSpeakerCP, List<IpAddress> wanIps, List<IpPrefix> peers,
                                          Short type) {

            FilteredConnectPoint bgpSpeakerFilteredCP = new FilteredConnectPoint(bgpSpeakerCP);
            Integer peerSize = peers.size();

            Set<FilteredConnectPoint> ingressFilteredCPs = Sets.newHashSet();

            for (int i = 0; i < peerSize; i++) {
                ConnectPoint peerCP = interfaceService.getMatchingInterface(wanIps.get(i))
                        .connectPoint();

                IpPrefix peer = peers.get(i);

                TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
                selector.matchEthType(type);

                if (type == Ethernet.TYPE_IPV4)
                    selector.matchIPDst(peer);
                else if (type == Ethernet.TYPE_IPV6)
                    selector.matchIPv6Dst(peer);

                FilteredConnectPoint ingressFilteredCP = new FilteredConnectPoint(peerCP, selector.build());
                ingressFilteredCPs.add(ingressFilteredCP);
            }

            MultiPointToSinglePointIntent.Builder intentBuilder = MultiPointToSinglePointIntent.builder()
                    .key(makeIntentKey("Ingress", ingressFilteredCPs, bgpSpeakerFilteredCP, type))
                    .appId(appId)
                    .filteredIngressPoints(ingressFilteredCPs)
                    .filteredEgressPoint(bgpSpeakerFilteredCP)
                    .priority(30);

            log.info("Submitting type 0x{} ingress intent", Integer.toHexString(type & 0xFFFF));
            intentService.submit(intentBuilder.build());
        }
    }

    private IpAddress getWanPortIp(ConnectPoint connectPoint, List<IpAddress> wanPortIp) {
        for (IpAddress wanIp : wanPortIp) {
            ConnectPoint cp = interfaceService.getMatchingInterface(wanIp).connectPoint();
            if (cp.equals(connectPoint)) {
                log.info("conectpoint: {} wanIp: {}", cp, wanIp);
                return wanIp;
            }
        }
        return null;
    }

    private IpPrefix getPeerPrefix(IpAddress ip, List<IpPrefix> peers) {
        if (ip == null)
            return null;
        for (IpPrefix peer : peers) {
            if (peer.contains(ip)) {
                return peer;
            }
        }
        return null;
    }

    private boolean isWanPort(ConnectPoint connectPoint) {
        for (IpAddress wanIp : wanPortIp4) {
            ConnectPoint cp = interfaceService.getMatchingInterface(wanIp).connectPoint();
            if (cp.equals(connectPoint)) return true;
        }
        for (IpAddress wanIp : wanPortIp6) {
            ConnectPoint cp = interfaceService.getMatchingInterface(wanIp).connectPoint();
            if (cp.equals(connectPoint)) return true;
        }
        return false;
    }

    private boolean isBgpSpeakerPort(ConnectPoint connectPoint) {
        return connectPoint.equals(frrCP);
    }

    private boolean isInSameSubnet(IpAddress ip, IpPrefix ipPrefix) {
        return ipPrefix != null && ipPrefix.contains(ip);
    }

    private class VirtualRouterProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {

            ConnectPoint connectPoint = context.inPacket().receivedFrom();
            Ethernet pkt = context.inPacket().parsed();

            if (pkt == null) {
                return;
            }

            Short type = pkt.getEtherType();

            // Block direct peer-to-peer traffic
            // Requirement: AS65xx1 → AS65yy1 must go via IXP, not directly through us
            if (isWanPort(connectPoint) && !isBgpSpeakerPort(connectPoint)) {
                IpAddress dstIp = null;
                IpAddress srcIp = null;

                // Extract source and destination IPs
                if (type == Ethernet.TYPE_IPV4) {
                    IPv4 ipv4Packet = (IPv4) pkt.getPayload();
                    dstIp = IpAddress.valueOf(ipv4Packet.getDestinationAddress());
                    srcIp = IpAddress.valueOf(ipv4Packet.getSourceAddress());
                } else if (type == Ethernet.TYPE_IPV6) {
                    IPv6 ipv6Packet = (IPv6) pkt.getPayload();
                    dstIp = IpAddress.valueOf(Version.INET6, ipv6Packet.getDestinationAddress());
                    srcIp = IpAddress.valueOf(Version.INET6, ipv6Packet.getSourceAddress());
                }

                if (dstIp != null && srcIp != null) {
                    // Get the peer prefix of the incoming port
                    List<IpAddress> wanIps = type == Ethernet.TYPE_IPV4 ? wanPortIp4 : wanPortIp6;
                    List<IpPrefix> peers = type == Ethernet.TYPE_IPV4 ? v4Peer : v6Peer;

                    IpPrefix ingressPeerPrefix = getPeerPrefix(getWanPortIp(connectPoint, wanIps), peers);

                    if (ingressPeerPrefix != null) {
                        // Check if destination is another peer (not our AS, not IXP)
                        for (IpPrefix peerPrefix : peers) {
                            // Skip the ingress peer prefix and IXP prefix
                            if (peerPrefix.equals(ingressPeerPrefix)) {
                                continue;
                            }

                            // Check if destination is in another peer's prefix
                            if (peerPrefix.contains(dstIp)) {
                                log.info("PEER FILTER: Blocking direct peer traffic from {} to {} " +
                                        "(must go via IXP)", ingressPeerPrefix, dstIp);
                                context.block();
                                return;  // Block this packet
                            }
                        }

                        // Also block if source is from transit AS (AS65xx1) and dst is peer
                        // Transit prefix: 172.17.x.0/24 or 2a0b:4e07:c4:1x::/64
                        IpPrefix transitPrefix4 = type == Ethernet.TYPE_IPV4 ?
                                IpPrefix.valueOf("172.17." + vrouterGatewayIpv4.toString().split("\\.")[2] + ".0/24") :
                                null;
                        IpPrefix transitPrefix6 = type == Ethernet.TYPE_IPV6 ?
                                IpPrefix.valueOf("2a0b:4e07:c4:1" + vrouterGatewayIpv6.toString().split(":")[3] + "::/64") :
                                null;

                        IpPrefix transitPrefix = type == Ethernet.TYPE_IPV4 ? transitPrefix4 : transitPrefix6;

                        if (transitPrefix != null && transitPrefix.contains(srcIp)) {
                            // Packet from our transit AS (AS65xx1)
                            for (IpPrefix peerPrefix : peers) {
                                if (peerPrefix.contains(dstIp)) {
                                    log.info("PEER FILTER: Blocking transit-to-peer traffic from AS65xx1 ({}) " +
                                            "to peer {} (must go via IXP)", srcIp, dstIp);
                                    context.block();
                                    return;  // Block this packet
                                }
                            }
                        }
                    }
                }
            }

            if (type != Ethernet.TYPE_IPV4 && type != Ethernet.TYPE_IPV6) {
                return;
            }

            MacAddress dstMac = pkt.getDestinationMAC();
            if (type == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) pkt.getPayload();
                IpAddress dstIp = IpAddress.valueOf(ipv4Packet.getDestinationAddress());

                if (dstMac.equals(vrouterMac)) {
                    ResolvedRoute bestRoute = getBestRoute(dstIp);
                    
                   if (bestRoute != null) {
                        IpAddress nextHopIp = bestRoute.nextHop();
                        MacAddress nextHopMac = arpTable.get(nextHopIp);
                        if (nextHopMac == null) {
                            log.info("No ARP entry for next hop {}, wait for ARP/NDP resolution", nextHopIp);
                            context.block();  // let ARP happen; packet-in will retry
                            return;
                        }
                        Interface outIntf = interfaceService.getMatchingInterface(nextHopIp);
                        if (outIntf == null) {
                            log.warn("No interface found for IPv4 next hop {}", nextHopIp);
                            return;
                        }
                        ConnectPoint outCP = outIntf.connectPoint();

                        installExternalIntent(context, connectPoint, outCP, vrouterMac, nextHopMac, dstIp,
                                Ethernet.TYPE_IPV4);
                    } 
                } else if (dstMac.equals(frrMac)) {
                    Set<Host> dstHosts = hostService.getHostsByIp(dstIp);
                    log.info("dstHost: {}", dstHosts);
                    if (!dstHosts.isEmpty()) {
                        Host targetHost = null;

                        // Anycast Logic: Prefer host on the same device as ingress
                        DeviceId ingressDevice = connectPoint.deviceId();
                        for (Host h : dstHosts) {
                            if (h.location().deviceId().equals(ingressDevice)) {
                                targetHost = h;
                                break;
                            }
                        }
                        // Fallback if no local host found
                        if (targetHost == null) {
                            targetHost = dstHosts.iterator().next();
                        }

                        ConnectPoint hostCP = targetHost.location();
                        MacAddress hostMAC = targetHost.mac();

                        installExternalIntent(context, connectPoint, hostCP, vrouterMac, hostMAC, dstIp, Ethernet.TYPE_IPV4);
                        context.block();
                    } else {
                        ResolvedRoute bestRoute = getBestRoute(dstIp);
                        if (bestRoute != null) {
                            IpAddress nextHopIp = bestRoute.nextHop();
                            MacAddress nextHopMAC = arpTable.get(nextHopIp);

                            Interface outIntf = interfaceService.getMatchingInterface(nextHopIp);
                            if (outIntf == null) {
                                log.warn("No interface found for IPv4 next hop {}", nextHopIp);
                                return;
                            }
                            ConnectPoint outCP = outIntf.connectPoint();

                            installExternalIntent(context, connectPoint, outCP, frrMac, nextHopMAC, dstIp,
                                    Ethernet.TYPE_IPV4);
                            context.block();
                        }
                    }
                }
            } else if (type == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Packet = (IPv6) pkt.getPayload();
                
                // Skip NDP packets (Neighbor Solicitation/Advertisement)
                // Let ProxyArpProcessor handle them.
                if (ipv6Packet.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                    IPacket payload = ipv6Packet.getPayload();
                    if (payload instanceof ICMP6) {
                        ICMP6 icmp6 = (ICMP6) payload;
                        byte icmpType = icmp6.getIcmpType();
                        if (icmpType == ICMP6.NEIGHBOR_SOLICITATION || 
                            icmpType == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                            return; 
                        }
                    }
                }
                
                IpAddress dstIp = IpAddress.valueOf(Version.INET6, ipv6Packet.getDestinationAddress());

                if (dstMac.equals(vrouterMac)) {
                    ResolvedRoute bestRoute = getBestRoute(dstIp);
                    if (bestRoute != null) {

                        IpAddress nextHopIp = bestRoute.nextHop();
                        MacAddress nextHopMac = arpTable.get(nextHopIp);

                        Interface outIntf = interfaceService.getMatchingInterface(nextHopIp);
                        if (outIntf == null) {
                            log.warn("No interface found for IPv4 next hop {}", nextHopIp);
                            return;
                        }

                        if (nextHopMac == null) {
                            log.info("IPv6 next hop MAC unknown, sending NDP solicitation for {}", nextHopIp);
                                sendNdpSolicitation(nextHopIp, outIntf.connectPoint());
                            return;
                        }

                        ConnectPoint outCP = outIntf.connectPoint();

                        installExternalIntent(context, connectPoint, outCP, vrouterMac, nextHopMac, dstIp,
                                Ethernet.TYPE_IPV6);
                    }
                } else if (dstMac.equals(frrMac)) {
                    Set<Host> dstHosts = hostService.getHostsByIp(dstIp);
                    log.info("dstHost: {}", dstHosts);
                    if (!dstHosts.isEmpty()) {
                        Host targetHost = null;

                        // Anycast Logic: Prefer host on the same device as ingress
                        DeviceId ingressDevice = connectPoint.deviceId();
                        for (Host h : dstHosts) {
                            if (h.location().deviceId().equals(ingressDevice)) {
                                targetHost = h;
                                break;
                            }
                        }
                        // Fallback if no local host found
                        if (targetHost == null) {
                            targetHost = dstHosts.iterator().next();
                        }

                        ConnectPoint hostCP = targetHost.location();
                        MacAddress hostMAC = targetHost.mac();

                        installExternalIntent(context, connectPoint, hostCP, vrouterMac, hostMAC, dstIp, Ethernet.TYPE_IPV6);
                        context.block();
                    } else {
                        ResolvedRoute bestRoute = getBestRoute(dstIp);
                        if (bestRoute != null) {
                            IpAddress nextHopIp = bestRoute.nextHop();
                            MacAddress nextHopMac = arpTable.get(nextHopIp);

                            Interface ndpIntf = interfaceService.getMatchingInterface(nextHopIp);
                            if (ndpIntf != null) {
                                sendNdpSolicitation(nextHopIp, ndpIntf.connectPoint());
                            } else {
                                log.warn("No interface found for IPv6 next hop {}", nextHopIp);
                            }
                            Interface outIntf = interfaceService.getMatchingInterface(nextHopIp);
                            if (outIntf == null) {
                                log.warn("No interface found for IPv4 next hop {}", nextHopIp);
                                return;
                            }
                            ConnectPoint outCP = outIntf.connectPoint();

                            installExternalIntent(context, connectPoint, outCP, frrMac, nextHopMac, dstIp,
                                    Ethernet.TYPE_IPV6);
                            context.block();
                        }
                    }
                }
            }
        }

        private void installExternalIntent(PacketContext context, ConnectPoint ingress, ConnectPoint egress,
                                           MacAddress srcMac, MacAddress dstMac, IpAddress dstIp, Short type) {

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                    .matchEthType(type);

            if (type == Ethernet.TYPE_IPV4)
                selector.matchIPDst(dstIp.toIpPrefix());
            else if (type == Ethernet.TYPE_IPV6)
                selector.matchIPv6Dst(dstIp.toIpPrefix());

            log.info("srcmac: {}", srcMac);
            log.info("dstmac: {}", dstMac);
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                    .setEthSrc(srcMac)
                    .setEthDst(dstMac);
            //.setOutput(egress.port());

            FilteredConnectPoint ingressPoint = new FilteredConnectPoint(ingress);
            FilteredConnectPoint egressPoint = new FilteredConnectPoint(egress);

            log.info("[SDN_External] " + ingress + " => " + egress + " is submitted.");

            PointToPointIntent intent = PointToPointIntent.builder()
                    .key(makeIntentKey("External",Sets.newHashSet(ingressPoint),egressPoint,type))
                    .filteredIngressPoint(ingressPoint)
                    .filteredEgressPoint(egressPoint)
                    .selector(selector.build())
                    .treatment(treatment.build())
                    .priority(Intent.DEFAULT_INTENT_PRIORITY)
                    .appId(appId)
                    .build();
            intentService.submit(intent);
        }

        private ResolvedRoute getBestRoute(IpAddress targetIp) {
            Collection<RouteTableId> routingTable = routeService.getRouteTables();
            for (RouteTableId tableID : routingTable) {
                for (RouteInfo info : routeService.getRoutes(tableID)) {
                    Optional<ResolvedRoute> bestRoute = info.bestRoute();

                    if (!bestRoute.isPresent()) {
                        log.info("Route info don't contains bestroute: {}", info);
                        continue;
                    }

                    ResolvedRoute route = bestRoute.get();
                    IpPrefix dstPrefix = route.prefix(); /* 要到的 Ip Network */
                    log.info("dstPrefix: {} targetIp: {}", dstPrefix, targetIp);
                    if (dstPrefix.contains(targetIp)) {
                        return route;
                    }
                }
            }
            return null;
        }

        /**
         * Selects the nearest host from a set of anycast hosts.
         * Uses topology-aware distance calculation.
         *
         * @param hosts Set of hosts with the same IP address
         * @param ingressCP ConnectPoint where packet arrived
         * @return Host that is topologically closest to ingress
         */
        private Host selectNearestHost(Set<Host> hosts, ConnectPoint ingressCP) {
            if (hosts.isEmpty()) {
                return null;
            }

            if (hosts.size() == 1) {
                return hosts.iterator().next();
            }

            // Multiple hosts - select nearest one
            Host selectedHost = null;
            int minDistance = Integer.MAX_VALUE;

            DeviceId ingressDevice = ingressCP.deviceId();
            String ingressDevStr = ingressDevice.toString();

            for (Host h : hosts) {
                DeviceId hostDevice = h.location().deviceId();
                String hostDevStr = hostDevice.toString();

                int distance;

                // Same switch = distance 0
                if (ingressDevice.equals(hostDevice)) {
                    distance = 0;
                    log.info("Anycast: Host {} on same switch as ingress", h.mac());
                }
                // Topology-specific distance calculation for your 3-switch setup
                // OVS1 -- OVS2 -- OVS3
                else if ((ingressDevStr.contains("ovs1") && hostDevStr.contains("ovs2")) ||
                        (ingressDevStr.contains("ovs2") && hostDevStr.contains("ovs1"))) {
                    distance = 1;  // OVS1 ↔ OVS2 direct connection
                }
                else if ((ingressDevStr.contains("ovs2") && hostDevStr.contains("ovs3")) ||
                        (ingressDevStr.contains("ovs3") && hostDevStr.contains("ovs2"))) {
                    distance = 1;  // OVS2 ↔ OVS3 direct connection
                }
                else if ((ingressDevStr.contains("ovs1") && hostDevStr.contains("ovs3")) ||
                        (ingressDevStr.contains("ovs3") && hostDevStr.contains("ovs1"))) {
                    distance = 2;  // OVS1 ↔ OVS3 via OVS2
                }
                else {
                    // Unknown topology, use default distance
                    distance = 10;
                    log.warn("Anycast: Unknown switch pair {} and {}", ingressDevice, hostDevice);
                }

                if (distance < minDistance) {
                    minDistance = distance;
                    selectedHost = h;
                }
            }

            log.info("Anycast: Selected host {} at distance {} from ingress {}",
                    selectedHost.location(), minDistance, ingressCP);

            return selectedHost;
        }

        private void sendNdpSolicitation(IpAddress targetIp, ConnectPoint outCp) {
            if (targetIp == null || !targetIp.isIp6() || outCp == null) {
                return;
            }

            Ip6Address t = targetIp.getIp6Address();
            byte[] tb = t.toOctets();

            // Solicited-node multicast ff02::1:ffXX:XXXX
            byte[] snm = new byte[16];
            snm[0] = (byte) 0xff;
            snm[1] = (byte) 0x02;
            snm[11] = (byte) 0x01;
            snm[12] = (byte) 0xff;
            snm[13] = tb[13];
            snm[14] = tb[14];
            snm[15] = tb[15];

            // Ethernet multicast 33:33:ff:XX:XX:XX
            MacAddress dstMac = MacAddress.valueOf(
                    new byte[]{0x33, 0x33, (byte) 0xff, tb[13], tb[14], tb[15]}
            );

            NeighborSolicitation ns = new NeighborSolicitation();
            ns.setTargetAddress(t.toOctets());
            ns.addOption(NeighborDiscoveryOptions.TYPE_SOURCE_LL_ADDRESS,
                    vrouterMac.toBytes());

            ICMP6 icmp6 = new ICMP6();
            icmp6.setIcmpType(ICMP6.NEIGHBOR_SOLICITATION);
            icmp6.setIcmpCode((byte) 0);
            icmp6.setPayload(ns);

            IPv6 ipv6 = new IPv6();
            ipv6.setSourceAddress(vrouterGatewayIpv6.getIp6Address().toOctets());
            ipv6.setDestinationAddress(snm);
            ipv6.setNextHeader(IPv6.PROTOCOL_ICMP6);
            ipv6.setHopLimit((byte) 255);
            ipv6.setPayload(icmp6);

            Ethernet eth = new Ethernet();
            eth.setEtherType(Ethernet.TYPE_IPV6);
            eth.setSourceMACAddress(vrouterMac);
            eth.setDestinationMACAddress(dstMac);
            eth.setPayload(ipv6);

            OutboundPacket out = new DefaultOutboundPacket(
                    outCp.deviceId(),
                    DefaultTrafficTreatment.builder()
                            .setOutput(outCp.port())
                            .build(),
                    ByteBuffer.wrap(eth.serialize())
            );

            packetService.emit(out);
        }
      }

    private class ProxyArpProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            ConnectPoint connectPoint = context.inPacket().receivedFrom();

            Ethernet pkt = context.inPacket().parsed();

            if (pkt == null) {
                return;
            }

            Short type = pkt.getEtherType();

            if (type != Ethernet.TYPE_ARP && type != Ethernet.TYPE_IPV6) {
                return;
            }

            if (type == Ethernet.TYPE_ARP) {
                ARP arpPacket = (ARP) pkt.getPayload();
                IpAddress targetIp = IpAddress.valueOf(Version.INET, arpPacket.getTargetProtocolAddress());
                IpAddress senderIp = IpAddress.valueOf(Version.INET, arpPacket.getSenderProtocolAddress());
                MacAddress senderMac = MacAddress.valueOf(arpPacket.getSenderHardwareAddress());
                MacAddress targetMac = arpTable.get(targetIp);

                if (targetIp.equals(vrouterGatewayIpv4)) {
                    targetMac = vrouterMac;
                }

                if (!isWanPort(connectPoint) && !isBgpSpeakerPort(connectPoint)
                        && !targetIp.equals(vrouterGatewayIpv4)) {
                    return;
                }

                log.info("targetIp: {}, senderIp: {}, senderMac: {}, targetMac: {}, connectPoint: {}",
                        targetIp.getIp4Address(), senderIp.getIp4Address(), senderMac, targetMac, connectPoint);

                // Only put senderIp and senderMac into arpTable if the senderIp and the
                // connectPoint Ip is in the same subnet or the connectPoint is bgpSpeakerPort
                IpPrefix wanPortPrefix = getPeerPrefix(getWanPortIp(connectPoint, wanPortIp4), v4Peer);
                if (isBgpSpeakerPort(connectPoint) || isInSameSubnet(senderIp, wanPortPrefix))
                    arpTable.put(senderIp, senderMac);

                if (arpPacket.getOpCode() == ARP.OP_REQUEST) {
                    if (targetMac != null) {
                        Ethernet arpReply = ARP.buildArpReply(targetIp.getIp4Address(), targetMac, pkt);

                        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                .setOutput(connectPoint.port())
                                .build();

                        OutboundPacket packetOut = new DefaultOutboundPacket(
                                connectPoint.deviceId(),
                                treatment,
                                ByteBuffer.wrap(arpReply.serialize()));

                        packetService.emit(packetOut);

                    } else {
                        context.treatmentBuilder().setOutput(PortNumber.FLOOD);
                        context.send();
                    }

                }

            } else {
                IPv6 ipv6Packet = (IPv6) pkt.getPayload();
                IPacket icmp6Packet = ipv6Packet.getPayload();
                if (icmp6Packet.getPayload() instanceof NeighborSolicitation) {
                    NeighborSolicitation ns = (NeighborSolicitation) icmp6Packet.getPayload();
                    IpAddress targetIp = IpAddress.valueOf(Version.INET6, ns.getTargetAddress());
                    IpAddress senderIp = IpAddress.valueOf(Version.INET6, ipv6Packet.getSourceAddress());
                    MacAddress senderMac = pkt.getSourceMAC();
                    MacAddress targetMac = arpTable.get(targetIp);

                    if (targetIp.equals(vrouterGatewayIpv6)) {
                        targetMac = vrouterMac;
                    }

                    if (!isWanPort(connectPoint) && !isBgpSpeakerPort(connectPoint)
                            && !targetIp.equals(vrouterGatewayIpv6)) {
                        return;
                    }

                    log.info("targetIp: {}, senderIp: {}, senderMac: {}, targetMac: {}, connectPoint: {}",
                            targetIp.getIp6Address(), senderIp.getIp6Address(), senderMac, targetMac, connectPoint);

                    IpPrefix wanPortPrefix = getPeerPrefix(getWanPortIp(connectPoint, wanPortIp6), v6Peer);
                    if (isBgpSpeakerPort(connectPoint) || isInSameSubnet(senderIp, wanPortPrefix)) {
                        log.info("Put senderIp: {} senderMac: {} into arpTable", senderIp, senderMac);
                        arpTable.put(senderIp, senderMac);

                    }

                    if (targetMac != null) {

                        Ethernet ndpAdvPacket = NeighborAdvertisement
                                .buildNdpAdv(targetIp.getIp6Address(), targetMac, pkt);
                        // ONOS NDP bug fix: IPv6 hop-limit must be 255
                        IPv6 advIpv6 = (IPv6) ndpAdvPacket.getPayload();
                        advIpv6.setHopLimit((byte) 255);
                        ndpAdvPacket.setPayload(advIpv6);

                        // Send the generated Neighbor Advertisement packet
                        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                .setOutput(connectPoint.port())
                                .build();

                        OutboundPacket packetOut = new DefaultOutboundPacket(
                                connectPoint.deviceId(),
                                treatment,
                                ByteBuffer.wrap(ndpAdvPacket.serialize()));

                        log.info("Send NDP Adv packet to {}", connectPoint);
                        packetService.emit(packetOut);

                    } else {
                        // log.info("TABLE MISS. Send request to edge ports");
                        context.treatmentBuilder().setOutput(PortNumber.FLOOD);
                        context.send();
                    }
                }
                
                else if (icmp6Packet.getPayload() instanceof NeighborAdvertisement) {
    NeighborAdvertisement na = (NeighborAdvertisement) icmp6Packet.getPayload();

    IpAddress targetIp = IpAddress.valueOf(IpAddress.Version.INET6, na.getTargetAddress());

    // Trust the Ethernet source MAC (what actually arrived on the wire)
    MacAddress srcMac = pkt.getSourceMAC();
    ConnectPoint cp = context.inPacket().receivedFrom();

    // (optional) only learn on WAN/BGP ports, to avoid poisoning from LAN
    if (isWanPort(cp) || isBgpSpeakerPort(cp)) {
        log.info("[NDP] LEARN(NA) targetIp={} mac={} on {}", targetIp, srcMac, cp);
        arpTable.put(targetIp, srcMac);
             }
           }
      }
    }
   
   }

    private class LearningBridgeProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            ConnectPoint connectPoint = context.inPacket().receivedFrom();

            if (isWanPort(connectPoint)) {
                context.block();
                return;
            }

            Ethernet pkt = context.inPacket().parsed();

            if (pkt == null) {
                return;
            }

            macTables.putIfAbsent(connectPoint.deviceId(), Maps.newConcurrentMap());

            Short type = pkt.getEtherType();

            if (type != Ethernet.TYPE_IPV4 && type != Ethernet.TYPE_ARP && type != Ethernet.TYPE_IPV6) {
                return;
            }

            Map<MacAddress, PortNumber> macTable = macTables.get(connectPoint.deviceId());
            MacAddress srcMac = pkt.getSourceMAC();
            MacAddress dstMac = pkt.getDestinationMAC();

            if (macTable.get(srcMac) == null) {
                macTable.put(srcMac, connectPoint.port());
            }

            PortNumber outPort = macTable.get(dstMac);

            if (outPort != null) {
                context.treatmentBuilder().setOutput(outPort);

                ForwardingObjective objective = DefaultForwardingObjective.builder()
                        .withSelector(DefaultTrafficSelector.builder()
                                .matchEthSrc(srcMac)
                                .matchEthDst(dstMac)
                                .build())
                        .withTreatment(context.treatmentBuilder().build())
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .withPriority(20)
                        .fromApp(appId)
                        .makeTemporary(30)
                        .add();

                flowObjectiveService.forward(connectPoint.deviceId(), objective);
                context.send();

            } else {

                context.treatmentBuilder().setOutput(PortNumber.FLOOD);
                context.send();
            }

        }
    }
 }
