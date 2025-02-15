# MemShellParty

[![ci-test](https://img.shields.io/github/actions/workflow/status/reajason/memshellparty/test.yaml?label=Test%20CI&branch=master&style=flat-square)](https://github.com/ReaJason/MemShellParty/actions/workflows/test.yaml)
[![ci-release](https://img.shields.io/github/actions/workflow/status/reajason/memshellparty/release.yaml?label=Release%20CD&style=flat-square)](https://github.com/ReaJason/MemShellParty/actions/workflows/release.yaml)
[![release](https://img.shields.io/github/v/release/reajason/memshellparty?label=Release&style=flat-square)](https://github.com/ReaJason/MemShellParty/releases)
[![docker-pulls](https://img.shields.io/docker/pulls/reajason/memshell-party?label=DockerHub%20Pulls&style=flat-square)](https://hub.docker.com/r/reajason/memshell-party)
[![Telegram](https://img.shields.io/badge/Chat-Telegram-%2326A5E4?style=flat-square&logo=telegram&logoColor=%2326A5E4)](https://t.me/memshell)
[![OnlinePartyWebSite](https://img.shields.io/badge/WebSite-OnlineParty-%23646CFF?style=flat-square&logo=vite&logoColor=%23646CFF)](https://party.memshell.news)

MemShellParty 是一款可本地部署的一键生成常见中间件框架内存马的可视化平台，并且致力于打造内存马的全方位的学习平台。
在遍地是轮子的时代，是时候造车，带着大伙加速冲冲冲了。

MemShellParty 出现的原因有以下几个：

1. 工作中有时候客户会有个别中间件的内存马测试需求，这个时候临时写一个太慢又太烦，在不忙的时候作一个工具，有需求的时候生成一个多好（之前用 [Java Memshell Generator](https://github.com/pen4uin/java-memshell-generator)
生成了一个 WAS 的内存马不能用，调了半天修好了）。
2. 写 [Javassist](https://www.javassist.org/) 实在是太多了，字符串拼接的方式去弄方法 code
   实在是看瞎眼睛，又不好维护，代码组织合理的话其实都可以，不过做项目我还是推荐 [Byte Buddy](https://bytebuddy.net/)，高封装提供的
   API 很好用的。单个利用脚本的话确实 [Javassist](https://www.javassist.org/) 来得快，而且很多中间件也自带依赖直接能打。
3. [Java Memshell Generator](https://github.com/pen4uin/java-memshell-generator)
   的出现确实帮大忙了，但是其极少的交互逻辑对于一个应用来说是难以接受的，刚好学习了前端对 UX 也感兴趣（对 Desktop
   应用无感），必须得整一个玩玩。
4. 因为对自动化测试特别感兴趣，刚好找到了 [Testcontainers](https://testcontainers.com/)
   ，并且看了一圈武器化工具基本都是无测试的，所以尝试写写可行的集成测试分享分享，被测试包裹的代码，修改起来信心也大，同时也希望这个项目长久吧。
5. 特别多的师傅写了 Java 内存马相关的项目，不过都慢慢就不维护了（或者不公开代码了），我举手来整合一下，嘿嘿。

希望你能从这个项目学会或尝试做的：

1. 学会编写常见中间件框架的内存马编写方式。
2. 学会使用 [Testcontainers](https://testcontainers.com/) 做 Java 应用的集成测试。
3. 学会使用 GitHub Actions 编写 CI/CD，编写 CHANGELOG 并通过 CI 自动发布 Release。
4. 尝试使用 [Byte Buddy](https://bytebuddy.net/) 生成类，编写 Agent。
5. 尝试使用 Gradle 构建 Java 项目（platform 编写依赖版本管理，toolchain 可以在根项目设置 JDK17 环境下也能完成 JDK6 source
   code 的编译）

> [!WARNING]
> 本工具仅供安全研究人员、网络管理员及相关技术人员进行授权的安全测试、漏洞评估和安全审计工作使用。使用本工具进行任何未经授权的网络攻击或渗透测试等行为均属违法，使用者需自行承担相应的法律责任。

> [!TIP]
> 由于本人仅是安全产品研发，无实战经验，如使用或实现有相关疑问或者适配请求可提 issue 或加入 TG
> 交流群，欢迎一起学习交流

![normal_generator](asserts/normal_generator.png)

![agent_generator](asserts/agent_generator.png)

## 主要特性

- 无侵入性：生成的内存马不会影响目标中间件正常流量，即使同时注入十几个不同的内存马。
- 高可用性: 自带完备的 [CI 集成测试](https://github.com/ReaJason/MemShellParty/actions/workflows/test.yaml)
- 最小化: 尽可能精简内存马大小，高效传输。
- 强兼容性: 覆盖攻防场景下常见中间件和框架。

## 快速使用

### 在线站点

可直接访问 https://party.memshell.news （没做加速，搭建在 [Northflank](https://northflank.com/) US
节点上，访问较慢，Thanks [@xcxmiku](https://github.com/xcxmiku)），每次 Release 都会自动部署最新的镜像。

### 本地部署（推荐）

使用 docker 部署之后访问 http://127.0.0.1:8080

```bash
# 使用 Docker Hub 源，拉取最新的镜像
docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party reajason/memshell-party:latest

# 使用 Github Container Registry 源，拉取最新的镜像
docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party ghcr.io/reajason/memshell-party:latest

# 网络质量不太好？使用南大 Github Container Registry 镜像源
docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party ghcr.nju.edu.cn/reajason/memshell-party:latest
```

镜像是无状态的，在需要更新最新镜像时，直接移除新建就好了

```bash
# 移除之前部署的
docker rm -f memshell-party

# 使用之前的部署命令，重新部署（会自动拉取最新的镜像部署）
docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party reajason/memshell-party:latest
```

## 适配情况

已兼容 Java6 ~ Java8、Java9、Java11、Java17、Java21

### 中间件以及框架

| Tomcat（5 ~ 11）       | Jetty（6 ~ 11）          | GlassFish（3 ~ 7）     | Payara（5 ~ 6）        |
|----------------------|------------------------|----------------------|----------------------|
| Servlet              | Servlet                | Filter               | Filter               |
| Filter               | Filter                 | Listener             | Listener             |
| Listener             | Listener               | Valve                | Valve                |
| Valve                | ServletHandler - Agent | FilterChain - Agent  | FilterChain - Agent  |
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
| FilterChain - Agent  | FilterChain - Agent (6)    | ServletHandler - Agent | ServletHandler - Agent |
| ContextValve - Agent | ContextValve - Agent (6)   |                        |                        |
|                      | ServletHandler - Agent (7) |                        |                        |

| WebSphere（7 ~ 9）      | WebLogic （10.3.6  ~ 14） |
|-----------------------|-------------------------|
| Servlet               | Servlet                 |
| Filter                | Filter                  |
| Listener              | Listener                |
| FilterManager - Agent | ServletContext - Agent  |

| BES（9.5.x）           | TongWeb（6 ~ 7）       | InforSuite AS （9 ~ 10） | Apusic AS （9） |
|----------------------|----------------------|------------------------|---------------|
| Filter               | Filter               | Filter                 | Servlet       |
| Listener             | Listener             | Listener               | Filter        |
| Valve                | Valve                | Valve                  | Listener      |
| FilterChain - Agent  | FilterChain - Agent  | FilterChain - Agent    |               |
| ContextValve - Agent | ContextValve - Agent | ContextValve - Agent   |               |

### 内存马功能

- [x] Godzilla 哥斯拉
- [x] Behinder 冰蝎
- [x] 命令执行
- [x] Suo5
- [ ] AntSword 蚁剑
- [ ] Neo-reGeorg
- [ ] Custom

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
- [x] 原生反序列化（CB4）
- [x] Agent
- [x] XXL-JOB Executor
- [ ] JNDI
- [ ] JDBC 连接
- [ ] 其他常见反序列化

## How

1. 如何使用 bytebuddy 生成类，为属性赋值，添加方法，指定位置调用方法？（**WIP**）
2. 如何调试内存马，为什么内存马注入了却不可用？（**WIP**）

## Contribute

> 你的任何反馈以及 issue 交流都是对当前项目的贡献

> It will be so nice if you want to contribute. 🎉

1. 如果你有高超的 Docker 环境构建技术，可以尝试添加 CVE 相关的集成测试用例。
2. 如果你有高超的内存马编写技术，可以尝试添加一个内存马试试。
3. 如果你有丰富的实战经验，可以尝试写写 issue 来提提建议。

项目结构目录、构建和编译可参考 [CONTRIBUTING.md](CONTRIBUTING.md)。

## Thanks

- [pen4uin/java-memshell-generator](https://github.com/pen4uin/java-memshell-generator)

### Let's start the party 🎉