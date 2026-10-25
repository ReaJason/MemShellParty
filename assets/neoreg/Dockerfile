FROM python:3.12-slim

WORKDIR /app

# CI runner 在境外，访问 USTC 镜像偶发超时；加宽超时重试，失败后回退官方 PyPI
RUN pip install --timeout 60 --retries 5 requests -i https://pypi.mirrors.ustc.edu.cn/simple \
    || pip install --timeout 60 --retries 5 requests

COPY neoreg.py .

CMD ["tail", "-f", "/dev/null"]
