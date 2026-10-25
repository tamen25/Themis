FROM scratch
COPY themis-dependency-fixture /themis-dependency-fixture
USER 65532:65532
ENTRYPOINT ["/themis-dependency-fixture"]
