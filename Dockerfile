FROM rust:1-alpine3.23 AS build
RUN apk add --no-cache build-base cmake perl linux-headers
WORKDIR /src
ENV RUSTFLAGS="-C target-feature=+crt-static"
COPY Cargo.toml Cargo.lock ./
COPY src ./src
#KEEP STATIC FLAGS OFF HOST PROC-MACROS
RUN target="$(rustc -vV | sed -n 's/^host: //p')" && \
    cargo build --release --locked --target "$target" && \
    cp "target/$target/release/oidc-drop" /src/oidc-drop
RUN readelf -h /src/oidc-drop && \
    ! readelf -l /src/oidc-drop | grep INTERP

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /src/oidc-drop /usr/local/bin/oidc-drop
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/oidc-drop"]
