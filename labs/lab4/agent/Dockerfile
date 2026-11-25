FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Nginx (веб-цель), rsyslog (создает /var/log/auth.log), nano (правка ossec.conf)
# и агент Wazuh. Версия агента зафиксирована и должна совпадать с версией менеджера (4.7.3):
# менеджер не принимает агентов новее себя.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release apt-transport-https \
        nginx rsyslog nano \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="wazuh.manager" apt-get install -y wazuh-agent=4.7.3-1 \
    && rm -rf /var/lib/apt/lists/*

# Скрипт запуска: rsyslog, nginx, агент, затем вывод лога nginx (держит контейнер запущенным)
RUN printf '%s\n' \
        '#!/bin/bash' \
        'service rsyslog start' \
        'service nginx start' \
        'service wazuh-agent start' \
        'exec tail -F /var/log/nginx/access.log' \
        > /start.sh && chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]
