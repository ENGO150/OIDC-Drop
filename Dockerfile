FROM rust:1-alpine3.23 AS build
RUN apk add --no-cache build-base cmake perl linux-headers
WORKDIR /src
ENV RUSTFLAGS="-C target-feature=+crt-static"
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked
RUN readelf -h target/release/oidc-drop && \
    ! readelf -l target/release/oidc-drop | grep INTERP

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /src/target/release/oidc-drop /usr/local/bin/oidc-drop
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/oidc-drop"]
