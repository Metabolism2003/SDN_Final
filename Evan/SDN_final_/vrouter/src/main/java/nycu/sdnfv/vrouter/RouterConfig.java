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

import java.util.List;
import java.util.ArrayList;
import java.util.function.Function;

import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.config.Config;

public class RouterConfig extends Config<ApplicationId> {


    public String gatewayMac() {
        return get("gateway-mac", null);
    }
    
    public String gatewayIpv4() {
        return get("gateway-ip4", null);
    }

    public String gatewayIpv6() {
        return get("gateway-ip6", null);
    }

    public String frroutingConnectPoint() {
        return get("frrouting-cp", null);
    }

    public String frroutingMac() {
        return get("frrouting-mac", null);
    }

    public List<IpAddress> wanPortIp4() {
        List<String> rawList = getList("wan-port-ip4", Function.identity());
        List<IpAddress> cplist = new ArrayList<>();
        for (String cp : rawList) {
            cplist.add(IpAddress.valueOf(cp));
        }

        return cplist;
    }

    public List<IpAddress> wanPortIp6() {
        List<String> rawList = getList("wan-port-ip6", Function.identity());
        List<IpAddress> cplist = new ArrayList<>();
        for (String cp : rawList) {
            cplist.add(IpAddress.valueOf(cp));
        }

        return cplist;
    }

    public List<IpPrefix> v4Peer() {
        List<String> rawList = getList("v4-peer", Function.identity());
        List<IpPrefix> cplist = new ArrayList<>();
        for (String cp : rawList) {
            cplist.add(IpPrefix.valueOf(cp));
        }

        return cplist;
    }

    public List<IpPrefix> v6Peer() {
        List<String> rawList = getList("v6-peer", Function.identity());
        List<IpPrefix> cplist = new ArrayList<>();
        for (String cp : rawList) {
            cplist.add(IpPrefix.valueOf(cp));
        }

        return cplist;
    }
}
