FROM ubuntu:24.04

LABEL description="Decoder for ECTF"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    curl\
    pkg-config\
    libssl-dev\
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    libtool \
    texinfo \
    unzip   

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --profile minimal --default-toolchain nightly -y

ENV RUSTUP_HOME="/root/.rustup" \
    CARGO_HOME="/root/.cargo" \
    PATH="/root/.cargo/bin:${PATH}"

RUN cargo install cargo-generate
RUN rustup default nightly
RUN rustup target add thumbv7em-none-eabihf
WORKDIR /decoder


ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.bin /out"]
