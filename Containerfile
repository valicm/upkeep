# The upkeep server as a container image: the static binary and nothing it does not need.
#
#   scripts/build.sh                      # puts the binaries into dist/
#   podman build -t localhost/upkeep .    # picks the one for this machine's architecture
#   podman build --platform linux/arm64 -t localhost/upkeep:arm64 .   # for another one
#
# What is in the image: /usr/local/bin/upkeep, the certificate authorities (the server speaks
# https to registries and appliances), the time zones (TZ decides when "daily 07:00" is), a
# user that is not root, and /var/lib/upkeep, the data directory, as a volume.
# What is not: a shell. The configuration is mounted at /etc/upkeep (see deploy/quadlet).

# This stage only gathers files, so it runs on the building machine whatever the image is
# for: "podman build --platform linux/arm64" on an amd64 machine needs no emulation.
FROM --platform=$BUILDPLATFORM docker.io/library/debian:trixie AS files
ARG TARGETARCH
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends ca-certificates tzdata
COPY dist/ /dist/
RUN set -eu; \
    case "$TARGETARCH" in arm) name=upkeep-linux-armv7 ;; *) name="upkeep-linux-$TARGETARCH" ;; esac; \
    install -D -m 0755 "/dist/$name" /rootfs/usr/local/bin/upkeep; \
    install -d -m 0755 /rootfs/etc/upkeep /rootfs/etc/ssl/certs /rootfs/usr/share; \
    install -d -m 1777 /rootfs/tmp; \
    install -d -m 0750 -o 65532 -g 65532 /rootfs/var/lib/upkeep; \
    cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt; \
    cp -r /usr/share/zoneinfo /rootfs/usr/share/zoneinfo; \
    printf 'root:x:0:0:root:/:/sbin/nologin\nupkeep:x:65532:65532:upkeep:/var/lib/upkeep:/sbin/nologin\n' >/rootfs/etc/passwd; \
    printf 'root:x:0:\nupkeep:x:65532:\n' >/rootfs/etc/group

FROM scratch
COPY --from=files /rootfs/ /
USER 65532:65532
VOLUME /var/lib/upkeep
EXPOSE 8484
ENTRYPOINT ["/usr/local/bin/upkeep"]
# The configuration has to say listen = "0.0.0.0:8484": the default only listens inside the container.
CMD ["server", "-config", "/etc/upkeep/server.toml"]
