FROM ubuntu:24.04 AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake ninja-build \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build \
 && ctest --test-dir build --output-on-failure

FROM ubuntu:24.04
COPY --from=build /src/build/routeguard /usr/local/bin/routeguard
COPY data /data
ENTRYPOINT ["routeguard"]
CMD ["--roas", "/data/sample_roas.csv", "--updates", "/data/sample_updates.txt", "--all"]
