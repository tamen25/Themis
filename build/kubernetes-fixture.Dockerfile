FROM scratch
COPY themis-kube-fixture /themis-kube-fixture
USER 65532:65532
ENTRYPOINT ["/themis-kube-fixture"]
