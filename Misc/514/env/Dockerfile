FROM node:lts-alpine

RUN apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont font-noto-cjk

COPY ./src /koishi
COPY ./entrypoint.sh /tmp/entrypoint.sh
COPY start.sh /tmp/start114514.sh
COPY ./ws_status.js /tmp/ws_status.js

WORKDIR "/koishi"

RUN chmod 755 /tmp/start114514.sh /tmp/ws_status.js /tmp/entrypoint.sh \
    && chown -R node:node /koishi /tmp/start114514.sh /tmp/ws_status.js /tmp/entrypoint.sh

USER node

COPY flag /flag

ENTRYPOINT ["/tmp/entrypoint.sh"]

EXPOSE 5140

#CMD ["yarn","start"]
CMD ["sh","-c","/tmp/start114514.sh"]



