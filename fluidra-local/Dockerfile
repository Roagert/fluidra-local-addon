ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.12-alpine3.20
FROM ${BUILD_FROM}

RUN apk add --no-cache bash curl iproute2 iputils jq
WORKDIR /app
COPY fluidra_local.py /app/fluidra_local.py
COPY emulator_flows.py /app/emulator_flows.py
COPY requirements.txt /app/requirements.txt
RUN if [ -s /app/requirements.txt ]; then pip3 install --no-cache-dir -r /app/requirements.txt; fi
COPY run.sh /run.sh
RUN chmod a+x /run.sh
EXPOSE 8765
CMD ["/run.sh"]
