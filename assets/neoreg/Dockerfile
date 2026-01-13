FROM python:3.12-slim

WORKDIR /app

RUN pip install requests -i https://pypi.tuna.tsinghua.edu.cn/simple/

COPY neoreg.py .

CMD ["tail", "-f", "/dev/null"]