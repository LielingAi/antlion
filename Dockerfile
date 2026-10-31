# AI 蜜罐 — 全栈容器
FROM python:3.13-slim

WORKDIR /app
ARG INSTALL_DEEPTEAM=0
COPY requirements.txt requirements-deepteam.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$INSTALL_DEEPTEAM" = "1" ]; then \
         pip install --no-cache-dir -r requirements-deepteam.txt; \
       fi
COPY . .

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

# 传感器形态 (main.py --server): HTTP 蜜罐 8080 (+C2 9999)
# hive 形态 (experiments/dashboard.py): 控制台 8899
# 假 PostgreSQL/Redis 仅实验形态 (experiments/real_runner 内嵌) 提供, 生产容器不起
EXPOSE 8080 8899

CMD ["python", "main.py", "--server", "--port", "8080"]
