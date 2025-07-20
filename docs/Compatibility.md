## 适配情况

已兼容 Java6 ~ Java8、Java9、Java11、Java17、Java21

### 中间件以及框架

| Tomcat（5 ~ 11）       | Jetty（6 ~ 11）          | GlassFish（3 ~ 7）     | Payara（5 ~ 6）        |
|----------------------|------------------------|----------------------|----------------------|
| Servlet              | Servlet                | Filter               | Filter               |
| Filter               | Filter                 | Listener             | Listener             |
| Listener             | Listener               | Valve                | Valve                |
| Valve                | ServletHandler - Agent | FilterChain - Agent  | FilterChain - Agent  |
| ProxyValve           |                        |                      |                      |
| FilterChain - Agent  |                        | ContextValve - Agent | ContextValve - Agent |
| ContextValve - Agent |                        |                      |                      |

| Resin（3 ~ 4）        | SpringMVC                | SpringWebFlux   | XXL-JOB      |
|---------------------|--------------------------|-----------------|--------------|
| Servlet             | Interceptor              | WebFilter       | NettyHandler |
| Filter              | ControllerHandler        | HandlerMethod   |              |
| Listener            | FrameworkServlet - Agent | HandlerFunction |              |
| FilterChain - Agent |                          | NettyHandler    |              |

| JBossAS（4 ~ 7）       | JBossEAP（6 ~ 7）            | WildFly（9 ~ 30）        | Undertow               |
|----------------------|----------------------------|------------------------|------------------------|
| Filter               | Filter                     | Servlet                | Servlet                |
| Listener             | Listener                   | Filter                 | Filter                 |
| Valve                | Valve(6)                   | Listener               | Listener               |
| ProxyValve           |                            |                        |                        |
| FilterChain - Agent  | FilterChain - Agent (6)    | ServletHandler - Agent | ServletHandler - Agent |
| ContextValve - Agent | ContextValve - Agent (6)   |                        |                        |
|                      | ServletHandler - Agent (7) |                        |                        |

| WebSphere（7 ~ 9）      | WebLogic （10.3.6  ~ 14） |
|-----------------------|-------------------------|
| Servlet               | Servlet                 |
| Filter                | Filter                  |
| Listener              | Listener                |
| FilterManager - Agent | ServletContext - Agent  |

| BES（9.5.x）           | TongWeb（6 ~ 8）       | InforSuite AS （9 ~ 10） |
|----------------------|----------------------|------------------------|
| Filter               | Filter               | Filter                 |
| Listener             | Listener             | Listener               |
| Valve                | Valve                | Valve                  |
| FilterChain - Agent  | FilterChain - Agent  | FilterChain - Agent    |
| ContextValve - Agent | ContextValve - Agent | ContextValve - Agent   |

| Apusic AS （9 ~ 10）  | Primeton（6.5）        |
|---------------------|----------------------|
| Servlet             | Filter               |
| Filter              | Listener             |
| Listener            | Valve                |
| FilterChain - Agent | FilterChain - Agent  |
|                     | ContextValve - Agent |

### 内存马功能

- [x] [Godzilla 哥斯拉](https://github.com/BeichenDream/Godzilla)
- [x] [Behinder 冰蝎](https://github.com/rebeyond/Behinder)
- [x] 命令执行
- [x] [Suo5](https://github.com/zema1/suo5)
- [x] [AntSword 蚁剑](https://github.com/AntSwordProject/antSword)
- [x] [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg)
- [x] Custom

### 封装方式

- [x] BASE64
- [x] GZIP BASE64
- [x] JSP
- [x] JSPX
- [x] JAR
- [x] BCEL
- [x] 内置脚本引擎、Rhino 脚本引擎
- [x] EL、SpEL、OGNL、Aviator、MVEL、JEXL、Groovy、JXPath、BeanShell
- [x] Velocity、Freemarker、JinJava
- [x] 原生反序列化（CB 和 CC 链）
- [x] Agent
- [x] XXL-JOB Executor
- [x] Hessian、Hessian2 反序列化（XSLT链）
- [ ] JNDI
- [ ] JDBC 连接
- [ ] 其他常见反序列化