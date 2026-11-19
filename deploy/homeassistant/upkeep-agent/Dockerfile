# The Supervisor builds this on the Home Assistant machine. BUILD_FROM is its base image for
# the machine's architecture (it has jq, which run.sh needs).
ARG BUILD_FROM
FROM $BUILD_FROM

# The upkeep binary for this machine, copied next to this file as "upkeep" before the app is
# installed: upkeep-linux-arm64 on a Raspberry Pi or Home Assistant Green/Yellow,
# upkeep-linux-amd64 on a PC.
COPY upkeep /usr/local/bin/upkeep
COPY run.sh /run.sh
RUN chmod 0755 /usr/local/bin/upkeep /run.sh

CMD ["/run.sh"]
