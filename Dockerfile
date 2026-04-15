FROM rust:1-bookworm

RUN apt-get update && apt-get install -y libpam0g-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

RUN cargo build --release

# The built library will be at /build/target/release/libpam_zxcvbn.so
