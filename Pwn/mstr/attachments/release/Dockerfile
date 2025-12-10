FROM ubuntu:24.04@sha256:440dcf6a5640b2ae5c77724e68787a906afb8ddee98bf86db94eea8528c2c076

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y xinetd python3 && \
    apt-get install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r ctf && useradd -r -m -g ctf ctf
WORKDIR /home/ctf

COPY ./mstr.py .
COPY ./flag.txt /
COPY ./Python-3.12.4 ./Python-3.12.4

WORKDIR /home/ctf/Python-3.12.4
RUN ./configure
RUN make -j10 
RUN make clean && make install -j10

RUN chown -R root:ctf /home/ctf && chmod -R 750 /home/ctf
RUN chown root:ctf /flag.txt && chmod 440 /flag.txt

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /start.sh
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail
RUN chmod +x /start.sh

WORKDIR /home/ctf
EXPOSE 9999

CMD ["/start.sh"]
