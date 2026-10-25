# 8.0 的 Nio2Channel 是异步 channel（Future 式 read/write），与 NIO 的 NioSelectorPool
# 是两条不同的裸连接路径；钉死 Http11Nio2Protocol 覆盖它。
FROM tomcat:8.0.53-jre8
RUN sed -i 's|protocol="HTTP/1.1"|protocol="org.apache.coyote.http11.Http11Nio2Protocol"|g' /usr/local/tomcat/conf/server.xml
