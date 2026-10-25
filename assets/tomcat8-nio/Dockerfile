# 官方 tomcat:8.0 镜像自带 tcnative，默认会把 HTTP/1.1 解析成 APR 连接器；
# 这里显式钉死 NIO，覆盖 8.0 独有的 NioSelectorPool 裸连接实现。
FROM tomcat:8.0.53-jre8
RUN sed -i 's|protocol="HTTP/1.1"|protocol="org.apache.coyote.http11.Http11NioProtocol"|g' /usr/local/tomcat/conf/server.xml
