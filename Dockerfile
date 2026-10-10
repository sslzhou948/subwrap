FROM python:3.12-slim

WORKDIR /app
# 只复制程序文件，不碰 .env / data（敏感配置和持久化数据留在宿主机）
COPY app.py qrcodegen.py /app/

EXPOSE 8080 8081
CMD ["python", "/app/app.py"]
