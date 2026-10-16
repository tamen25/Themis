FROM scratch
COPY themis-controller /themis-controller
USER 65532:65532
ENTRYPOINT ["/themis-controller"]
