deploy:
	# 0. Build the Java App (Added this step)
	cd vrouter && mvn clean install -DskipTests
	# 1. Deploy Topology
	cd topo && sudo ./topo_utils.sh deploy
	# 2. Wait for ONOS to wake up (robust)
	while true; do \
		n=$$(curl -s -u onos:rocks http://localhost:8181/onos/v1/devices \
			| grep -o '"available":true' | wc -l); \
		if [ "$$n" -ge 3 ]; then break; fi; \
		sleep 5; \
	done
	# 3. Generate Config
	cd topo && sudo ./topo_utils.sh gen-config ../vrouter/app-conf.json
	# 4. Push Config
	curl -u onos:rocks -X POST -H "Content-Type: application/json" \
		-d @vrouter/app-conf.json \
		http://localhost:8181/onos/v1/network/configuration
	# 5. Copy App to Container
	docker cp vrouter/target/vrouter-1.0-SNAPSHOT.oar onos:/root/onos/apps/
	# 6. Install App
	docker exec onos /root/onos/bin/onos-app localhost install! /root/onos/apps/vrouter-1.0-SNAPSHOT.oar
	# 7. Activate App
	docker exec onos /root/onos/bin/onos-app localhost activate nycu.sdnfv.vrouter
clean:
	cd topo && sudo ./topo_utils.sh clean
app:
	cd vrouter && mvn clean install -DskipTests
	docker cp vrouter/target/vrouter-1.0-SNAPSHOT.oar onos:/root/onos/apps/
	docker exec onos /root/onos/bin/onos-app localhost reinstall! /root/onos/apps/vrouter-1.0-SNAPSHOT.oar
	docker exec onos /root/onos/bin/onos-app localhost activate nycu.sdnfv.vrouter
