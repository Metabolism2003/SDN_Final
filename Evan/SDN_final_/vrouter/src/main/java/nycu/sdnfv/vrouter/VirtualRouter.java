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
					packetService.addProcessor(virtualRouterProcessor, PacketProcessor.director(1));
					packetService.addProcessor(arpProcessor, PacketProcessor.director(2));
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
			if (cp.equals(connectPoint)) {
				return true;
			}
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
			// If the next hop is in the IXP subnet (192.168.70.x), send to FRR
                        if (nextHopIp != null && nextHopIp.toString().startsWith("192.168.70.")) {
                            
                            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                    .setEthSrc(vrouterMac)
                                    .setEthDst(frrMac)
                                    .setOutput(frrCP.port())
                                    .build();

                            TrafficSelector selector = DefaultTrafficSelector.builder()
                                    .matchEthType(Ethernet.TYPE_IPV4)
                                    .matchIPDst(dstIp.toIpPrefix())
                                    .build();

                            PointToPointIntent intent = PointToPointIntent.builder()
                                    .appId(appId)
                                    .selector(selector)
                                    .treatment(treatment)
                                    .filteredIngressPoint(new FilteredConnectPoint(connectPoint))
                                    .filteredEgressPoint(new FilteredConnectPoint(frrCP))
                                    .priority(500) // High priority
                                    .build();

                            intentService.submit(intent);
                            return; // Stop here so we don't install the standard rule below
                        }  
						MacAddress nextHopMac = arpTable.get(nextHopIp);

						Interface outIntf = interfaceService.getMatchingInterface(nextHopIp);
						ConnectPoint outCP = outIntf.connectPoint();

						installExternalIntent(context, connectPoint, outCP, frrMac, nextHopMac, dstIp,
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
							ConnectPoint outCP = outIntf.connectPoint();

							installExternalIntent(context, connectPoint, outCP, frrMac, nextHopMAC, dstIp,
									Ethernet.TYPE_IPV4);
							context.block();
						}
					}
				}
			} else if (type == Ethernet.TYPE_IPV6) {
				IPv6 ipv6Packet = (IPv6) pkt.getPayload();
				IpAddress dstIp = IpAddress.valueOf(Version.INET6, ipv6Packet.getDestinationAddress());

				if (dstMac.equals(vrouterMac)) {
					ResolvedRoute bestRoute = getBestRoute(dstIp);
					if (bestRoute != null) {
						IpAddress nextHopIp = bestRoute.nextHop();
						
					/*	if (nextHopIp != null && nextHopIp.isIp6()) {
                                             TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                             .setEthSrc(vrouterMac)
                                             .setEthDst(frrMac)
                                             .setOutput(frrCP.port())
                                              .build();

                                              TrafficSelector selector = DefaultTrafficSelector.builder()
                                              .matchEthType(Ethernet.TYPE_IPV6)
                                              .matchIPv6Dst(dstIp.toIpPrefix())
                                              .build();

                                               Key key = Key.of("ipv6:" + dstIp + "->" + frrCP.deviceId(), appId);
                                               PointToPointIntent intent = PointToPointIntent.builder()
                                               .appId(appId)
                                               .key(key)
                                               .selector(selector)
                                               .treatment(treatment)
                                               .filteredIngressPoint(new FilteredConnectPoint(connectPoint))
                                               .filteredEgressPoint(new FilteredConnectPoint(frrCP))
                                               .priority(500)
                                               .build();

                                               intentService.submit(intent);
                                               return; 
                                               }   */
						MacAddress nextHopMac = arpTable.get(nextHopIp);
						
                                               if (nextHopMac == null) {
                                               // Trigger NDP for next hop, then wait for NA to populate arpTable
    sendNdpSolicitation(nextHopIp, interfaceService.getMatchingInterface(nextHopIp).connectPoint());
    return; }

						Interface outIntf = interfaceService.getMatchingInterface(nextHopIp);
						ConnectPoint outCP = outIntf.connectPoint();

						installExternalIntent(context, connectPoint, outCP, frrMac, nextHopMac, dstIp,
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
						
                                                        if (nextHopMac == null) {
                                               // Trigger NDP for next hop, then wait for NA to populate arpTable
    sendNdpSolicitation(nextHopIp, interfaceService.getMatchingInterface(nextHopIp).connectPoint());
    return; }
							Interface outIntf = interfaceService.getMatchingInterface(nextHopIp);
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
			
			
                        // Create a unique key string based on the selector and input/output points
                        String keyString = selector.build().toString() + ingressPoint.toString() + egressPoint.toString();
                        Key key = Key.of(keyString, appId);
			PointToPointIntent intent = PointToPointIntent.builder() //.key(key)
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
