# FRR Dockerfile with classic FPM support for ONOS integration
# Uses Debian packages from deb.frrouting.org which include zebra_fpm.so

FROM debian:bullseye-slim

LABEL maintainer="SDN-NFV-Final"

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gnupg2 \
    lsb-release \
    iproute2 \
    arping \
    mtr \
    telnet \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Add FRR GPG key and repository
RUN curl -s https://deb.frrouting.org/frr/keys.gpg | tee /usr/share/keyrings/frrouting.gpg > /dev/null

# Use frr-7 which has classic FPM support
RUN echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr $(lsb_release -s -c) frr-7" > /etc/apt/sources.list.d/frr.list

# Install FRR
RUN apt-get update && apt-get install -y \
    frr \
    frr-pythontools \
    && rm -rf /var/lib/apt/lists/*

# Create vtysh.conf to suppress warning
RUN touch /etc/frr/vtysh.conf && chown frr:frr /etc/frr/vtysh.conf

# Set permissions
RUN chown -R frr:frr /etc/frr

# Verify zebra_fpm.so exists
RUN test -f /usr/lib/x86_64-linux-gnu/frr/modules/zebra_fpm.so && \
    echo "SUCCESS: zebra_fpm.so found!"

# Create startup script that keeps container running
RUN echo '#!/bin/bash\n\
/usr/lib/frr/frrinit.sh start\n\
# Keep container running\n\
tail -f /dev/null\n\
' > /start.sh && chmod +x /start.sh

# Default command - start FRR and keep running
CMD ["/start.sh"]
