FROM node:lts-alpine

COPY ./src /koishi
COPY ./entrypoint.sh /entrypoint.sh
#RUN apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont font-noto-cjk

COPY flag /flag

COPY readflag /readflag

RUN chown root:root /readflag \
    && chmod 4755 /readflag \
    && chown root:root /flag \
    && chmod 0400 /flag

RUN chmod 755 /entrypoint.sh \
    && chown -R node:node /koishi /entrypoint.sh

USER node

WORKDIR "/koishi"

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 5140

CMD ["yarn","start"]



