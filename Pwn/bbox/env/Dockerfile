FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    libglib2.0-0 \
    libpixman-1-0 \
    libslirp0 \
    qemu-system-x86 \
    libxen-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf

WORKDIR /home/ctf

COPY ./qemu-system-x86_64 ./core.cpio ./vmlinuz ./run.sh ./start.sh /home/ctf/
COPY ./pc-bios /home/ctf/pc-bios/
COPY ./flag /flag

RUN chown -R root:root /home/ctf && \
    chmod -R 755 /home/ctf

RUN chmod 555 /home/ctf/qemu-system-x86_64 \
              /home/ctf/run.sh \
              /home/ctf/start.sh

RUN chmod 444 /home/ctf/core.cpio \
              /home/ctf/vmlinuz

RUN find /home/ctf/pc-bios -type d -exec chmod 555 {} \; && \
    find /home/ctf/pc-bios -type f -exec chmod 444 {} \;

RUN chown root:root /flag && chmod 444 /flag

USER ctf
EXPOSE 9999

CMD ["socat", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:/home/ctf/start.sh,stderr"]