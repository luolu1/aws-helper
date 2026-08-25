FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    AWS_HELPER_DATA=/data \
    AWS_HELPER_HOST=0.0.0.0 \
    AWS_HELPER_PORT=8765

WORKDIR /app

# curl 用于容器 healthcheck；依赖先装，利用层缓存
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY aws_helper /app/aws_helper

# 非 root 运行；/data 是挂载点，需提前给好归属
RUN useradd --system --create-home --shell /usr/sbin/nologin awshelper \
    && mkdir -p /data \
    && chown -R awshelper:awshelper /app /data \
    && chmod 700 /data

USER awshelper
VOLUME ["/data"]
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${AWS_HELPER_PORT}/healthz" || exit 1

CMD ["sh", "-c", "exec python -m uvicorn aws_helper.web.app:app --host \"$AWS_HELPER_HOST\" --port \"$AWS_HELPER_PORT\""]
