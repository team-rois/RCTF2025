# Default Dockerfile
#
# @link     https://www.hyperf.io
# @document https://hyperf.wiki
# @contact  group@hyperf.io
# @license  https://github.com/hyperf/hyperf/blob/master/LICENSE

FROM hyperf/hyperf:8.3-alpine-v3.19-swoole
LABEL maintainer="Hyperf Developers <group@hyperf.io>" version="1.0" license="MIT" app.name="Hyperf"

##
# ---------- env settings ----------
##
# --build-arg timezone=Asia/Shanghai
ARG timezone

ENV TIMEZONE=${timezone:-"Asia/Shanghai"} \
    APP_ENV=prod \
    SCAN_CACHEABLE=(true)

# update
RUN set -ex \
    # show php version and extensions
    && php -v \
    && php -m \
    && php --ri swoole \
    #  ---------- some config ----------
    && cd /etc/php* \
    # - config PHP
    && { \
        echo "upload_max_filesize=128M"; \
        echo "post_max_size=128M"; \
        echo "memory_limit=1G"; \
        echo "date.timezone=${TIMEZONE}"; \
        echo "open_basedir=/opt/www:/tmp"; \
    } | tee conf.d/99_overrides.ini \
    # - config timezone
    && ln -sf /usr/share/zoneinfo/${TIMEZONE} /etc/localtime \
    && echo "${TIMEZONE}" > /etc/timezone \
    # ---------- clear works ----------
    && rm -rf /var/cache/apk/* /tmp/* /usr/share/man \
    && echo -e "\033[42;37m Build Completed :).\033[0m\n"

RUN addgroup -S rois && adduser -S -G rois rois

WORKDIR /opt/www

# Composer Cache
# COPY ./composer.* /opt/www/
# RUN composer install --no-dev --no-scripts

COPY . /opt/www
COPY rctf_2025_flag /

RUN  echo "AES_KEY="$(openssl rand -base64 16) >> .env \
    && echo "DB_DATABASE=/opt/www/storage/database.db" >> .env \
     && cp database.db ./storage/database.db \
     && chown root:rois /rctf_2025_flag \
     && chmod 755 /rctf_2025_flag \
     && chown -R rois:rois /opt/www \
     && chmod 755 /opt/www \
     && chown root:root /opt/www/storage \
     && chmod 555 /opt/www/storage \
     && unzip vendor.zip \
     && rm vendor.zip



# RUN composer install --no-dev -o && php bin/hyperf.php

EXPOSE 9501

USER rois

ENTRYPOINT ["php", "/opt/www/bin/hyperf.php", "start"]
