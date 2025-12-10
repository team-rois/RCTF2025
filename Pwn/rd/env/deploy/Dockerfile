FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y xinetd socat && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r ctf && useradd -r -m -g ctf ctf

WORKDIR /home/ctf

COPY ./main .
COPY ./flag.txt .
COPY ./run.sh .  
COPY ./xinetd.conf /etc/xinetd.d/ctf

RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf

RUN chown root:ctf /home/ctf/flag.txt && \
    chmod 440 /home/ctf/flag.txt

RUN chown root:ctf /home/ctf/main && \
    chmod 750 /home/ctf/main

RUN chown root:ctf /home/ctf/run.sh && \
    chmod 750 /home/ctf/run.sh

EXPOSE 13331

CMD ["socat", "TCP-LISTEN:13331,reuseaddr,fork", "EXEC:./run.sh,su=ctf"]