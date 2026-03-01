FROM sagemath/sagemath:latest
USER root

RUN apt-get update -qq && apt-get install -y -qq wget \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://go.dev/dl/go1.24.2.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz \
    && rm go1.24.2.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /abom
COPY . .

RUN go test -v
RUN sage -t scripts/pw.py
