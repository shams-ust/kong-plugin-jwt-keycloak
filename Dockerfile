# STAGE 1: The Builder
FROM kong:latest as builder

USER root

# Install only what is needed to compile the rock
RUN apt-get update && apt-get install -y git build-essential unzip zip && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/jwt-keycloak

# 1. Clone your FIXED repository
RUN git clone --depth 1 --branch master https://github.com/shams-ust/kong-plugin-jwt-keycloak.git .

# 2. Build the portable .rock file (No 'sed' needed since code is already correct!)
RUN luarocks make *.rockspec && luarocks pack kong-plugin-jwt-keycloak

# STAGE 2: The Final Production Image
FROM kong:latest

ENV KONG_PLUGINS="bundled,jwt-keycloak"

USER root

# Copy only the finished plugin from the builder
COPY --from=builder /tmp/jwt-keycloak/*.rock /tmp/

# Install and cleanup
RUN luarocks install /tmp/*.rock && rm /tmp/*.rock

# Security: Run as kong user
USER kong
