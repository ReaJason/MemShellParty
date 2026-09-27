FROM python:3.12-slim

WORKDIR /app

RUN pip install requests -i https://pypi.mirrors.ustc.edu.cn/simple

COPY neoreg.py .

CMD ["tail", "-f", "/dev/null"]