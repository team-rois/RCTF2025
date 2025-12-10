FROM docker.1ms.run/ubuntu:22.04
# RUN sed -i 's@//.*.ubuntu.com@//mirrors.ustc.edu.cn@g' /etc/apt/sources.list
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y xinetd libicu-dev python3 python3-pip

RUN useradd -m ctf

WORKDIR /home/ctf

COPY ./xinetd.conf /etc/xinetd.d/ctf
COPY ./start.sh /start.sh

RUN chmod +x /start.sh

COPY ./read_the_flag /
COPY ./run.sh /
COPY ./server.py /
COPY ./flag /flag

RUN chmod +x /run.sh && chmod +x /server.py

RUN chmod 400 /flag && chmod 755 /read_the_flag && chmod +x /read_the_flag && chmod +s /read_the_flag

CMD ["/start.sh"]

EXPOSE 7000
