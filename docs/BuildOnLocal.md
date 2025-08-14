## 本地构建

### 源代码构建

> 适合想编写代码的小伙伴，使用 Git Clone 下载到本地，并构建前后端项目以供使用

首先需要下载 [bun](https://bun.sh/)，这是一款用于构建前端服务的工具。

1. 使用 Git Clone 项目

```bash
git clone https://github.com/ReaJason/MemShellParty.git
```

2. 构建前端项目，build 结束会将静态资源自动移动到 Spring Boot 中以供使用

```bash
cd MemShellParty/web

bun install

bun run build
```

3. 构建后端项目，确保使用 JDK17 环境

```bash
cd MemShellParty/boot

./gradlew :boot:bootjar -x test
```

构建完之后，可直接启动 jar 包，jar 包位于 `MemShellParty/boot/build/libs/boot-1.0.0.jar`

```bash
cd MemShellParty/boot

java -jar \
     --add-opens=java.base/java.util=ALL-UNNAMED \
     --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
     --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
     build/libs/boot-1.0.0.jar
```

也可这基础上再继续构建容器来使用

```bash
cd MemShellParty/boot

docker buildx build -t memshell-party:latest . --load

docker run -it -d --name memshell-party -p 8080:8080 memshell-party:latest
```

### Dockerfile 一键构建

> 适合于希望构建自定义访问路径的小伙伴，例如 NGINX 反代的场景（[#44](https://github.com/ReaJason/MemShellParty/issues/44)）

下载项目根目录的 [Dockerfile](./Dockerfile)

- ROUTE_ROOT_PATH: 前端根路由配置
- CONTEXT_PATH: 后端访问前缀

```bash
# 基础构建
docker buildx build \
    -t memshell-party:latest . --load

# 基础镜像启动，访问 127.0.0.1:8080
docker run -it -d -p 8080:8080 memshell-party:latest

# 自定义访问路径构建
docker buildx build \
    --build-arg ROUTE_ROOT_PATH=/memshell-party \
    --build-arg CONTEXT_PATH=/memshell-party \
    -t memshell-party:latest . --load
    
# 自定义路径构建镜像启动，访问 127.0.0.1:8080/memshell-party
docker run -it -p 8080:8080 \
    -e BOOT_OPTS=--server.servlet.context-path=/memshell-party \
    memshell-party:latest
```

如果需要使用 NGINX 反代，请先使用自定义访问路径构建容器，并配置 NGINX 如下：

其中 `location /memshell-party`、`ROUTE_ROOT_PATH=/memshell-party`、`CONTEXT_PATH=/memshell-party` 和
`BOOT_OPTS=--server.servlet.context-path=/memshell-party` 都要一致才行。

```text
location /memshell-party {
  proxy_pass http://127.0.0.1:8080;
  proxy_set_header Host $http_host;
  proxy_set_header X-Forwarded-By $server_addr:$server_port;
  proxy_set_header X-Forwarded-For $remote_addr;
  proxy_http_version 1.1;
  proxy_connect_timeout 3s;
  proxy_read_timeout 300s;
  proxy_send_timeout 300s;
  proxy_buffer_size 16k;
  proxy_buffers 8 64k;
  proxy_busy_buffers_size 128k;
}
```