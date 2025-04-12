<h1 align="center">MemShellParty</h1>

<p align="center">English | <a href="../README.md">中文</a><br></p>
<div align="center">

[![ci-test](https://img.shields.io/github/actions/workflow/status/reajason/memshellparty/test.yaml?label=Test%20CI&branch=master&style=flat-square)](https://github.com/ReaJason/MemShellParty/actions/workflows/test.yaml)
[![ci-release](https://img.shields.io/github/actions/workflow/status/reajason/memshellparty/release.yaml?label=Release%20CD&style=flat-square)](https://github.com/ReaJason/MemShellParty/actions/workflows/release.yaml)
</div>


<div align="center">

[![release](https://img.shields.io/github/v/release/reajason/memshellparty?label=Release&style=flat-square)](https://github.com/ReaJason/MemShellParty/releases)
[![MavenCentral](https://img.shields.io/maven-central/v/io.github.reajason/generator?label=MavenCentral&style=flat-square)](https://central.sonatype.com/artifact/io.github.reajason/generator)
[![docker-pulls](https://img.shields.io/docker/pulls/reajason/memshell-party?label=DockerHub%20Pulls&style=flat-square)](https://hub.docker.com/r/reajason/memshell-party)
</div>
<div align="center">

[![Telegram](https://img.shields.io/badge/Chat-Telegram-%2326A5E4?style=flat-square&logo=telegram&logoColor=%2326A5E4)](https://t.me/memshell)
[![OnlinePartyWebSite](https://img.shields.io/badge/WebSite-OnlineParty-%23646CFF?style=flat-square&logo=vite&logoColor=%23646CFF)](https://party.memshell.news)
</div>

> [!WARNING]
> This tool is intended only for security researchers, network administrators, and related technical personnel for authorized security testing, vulnerability assessment, and security auditing purposes. Using this tool for any unauthorized network attacks or penetration testing activities is illegal, and users are solely responsible for any resulting legal consequences.

> [!TIP]
> As I primarily focus on security product development and lack extensive real-world combat experience, please feel free to raise an issue or join the [Telegram group](https://t.me/memshell) if you have questions about usage, implementation, or adaptation requests. Let's learn and exchange ideas together!

MemShellParty is a locally deployable, visual platform for one-click generation of java memshell for common middleware and frameworks. It also aims to be a comprehensive learning platform for java memshell. In an era full of wheels, it's time to build the car and accelerate together!

What you can learn or try from this project:

1. Learn to write java memshell for common middleware and frameworks.
2. Learn to use [Testcontainers](https://testcontainers.com/) for Java application integration testing.
3. Learn to use GitHub Actions for CI/CD, write CHANGELOG, and automate Release publications via CI.
4. Try using [Byte Buddy](https://bytebuddy.net/) to generate classes and write Agents.
5. Try using Gradle to build Java projects (using platform for dependency version management, toolchain to compile JDK 6 source code even in a JDK 17 environment within the root project).

![normal_generator](../asserts/normal_generator.png)

![agent_generator](../asserts/agent_generator.png)

## Key Features

- Non-Intrusive: Generated memshell do not interfere with the normal traffic of the target middleware, even when multiple different shells are injected simultaneously.
- High Availability: Comes with comprehensive [CI integration tests](https://github.com/ReaJason/MemShellParty/actions/workflows/test.yaml)
- Minimal Size: Strives to minimize memshell size for efficient transfer.
- Strong Compatibility: Covers common middleware and frameworks encountered in offensive and defensive scenarios.

## Quick Start

### Online Preview

> Suitable for users who just want to try it out. Please use with caution on public services, as generated memshell might potentially contain backdoors if the service is compromised.

Access directly at [https://party.memshell.news](https://party.memshell.news). The latest image is automatically deployed with each release.

### Local Deployment (Recommended)

> Ideal for quick deployment on internal networks or local machines. Using Docker is fast and convenient.

After deploying with Docker, access the service at http://127.0.0.1:8080

```bash
# Pull the latest image from Docker Hub
docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party reajason/memshell-party:latest

# Pull the latest image from Github Container Registry
docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party ghcr.io/reajason/memshell-party:latest

# If network quality is poor, use the Nanjing University Github Container Registry mirror
docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party ghcr.nju.edu.cn/reajason/memshell-party:latest
```

The image is stateless. To update to the latest version, simply remove the old container and create a new one:

```bash
# Remove the previously deployed container
docker rm -f memshell-party

# Use the previous deployment command to redeploy (it will automatically pull the latest image)
docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party reajason/memshell-party:latest
```

### SDK Integration into Existing Tools

> Suitable for integrating memshell payload generation into your existing tools. Supports JDK 8 and above (since v1.7.0).

1. Add the dependency using Maven or Gradle:

```xml
<!-- Maven Repo-->
<dependency>
    <groupId>io.github.reajason</groupId>
    <artifactId>generator</artifactId>
    <version>1.7.0</version>
</dependency>
```

```groovy
// Gradle Repo
implementation 'io.github.reajason:generator:1.7.0'
```

2. Example1: Generate a Tomcat Godzilla Filter memory shell:

```java
ShellConfig shellConfig = ShellConfig.builder()
        .server(Server.Tomcat)
        .shellTool(ShellTool.Godzilla)
        .shellType(ShellType.FILTER)
        .shrink(true) // Shrink bytecode size
        .debug(false) // Disable debug mode
        .build();

InjectorConfig injectorConfig = InjectorConfig.builder()
//                .urlPattern("/*")  // Custom urlPattern, defaults to /*
//                .shellClassName("com.example.memshell.GodzillaShell") // Custom shell class name, random if empty
//                .injectorClassName("com.example.memshell.GodzillaInjector") // Custom injector class name, random if empty
        .build();

GodzillaConfig godzillaConfig = GodzillaConfig.builder()
//                .pass("pass")
//                .key("key")
//                .headerName("User-Agent")
//                .headerValue("test")
        .build();

GenerateResult result = MemShellGenerator.generate(shellConfig, injectorConfig, godzillaConfig);

System.out.println("Injector Class Name: "+result.getInjectorClassName());
System.out.println("MemShell Class Name: "+result.getShellClassName());

System.out.println(result.getShellConfig());
System.out.println(result.getShellToolConfig());

System.out.println("Base64 Packed: "+Packers.Base64.getInstance().pack(result));
System.out.println("ScriptEngine Packed: "+Packers.ScriptEngine.getInstance().pack(result));
```
3. Example2: Generate a Tomcat Godzilla AgentFilterChain memory shell (Agent type):
```java
ShellConfig shellConfig = ShellConfig.builder()
        .server(Server.Tomcat)
        .shellTool(ShellTool.Godzilla)
        .shellType(ShellType.AGENT_FILTER_CHAIN)
        .shrink(true) // Shrink bytecode size
        .debug(false) // Disable debug mode
        .build();

InjectorConfig injectorConfig = InjectorConfig.builder()
//                .urlPattern("/*")  // Custom urlPattern, defaults to /*
//                .shellClassName("com.example.memshell.GodzillaShell") // Custom shell class name, random if empty
//                .injectorClassName("com.example.memshell.GodzillaInjector") // Custom injector class name, random if empty
        .build();

GodzillaConfig godzillaConfig = GodzillaConfig.builder()
//                .pass("pass")
//                .key("key")
//                .headerName("User-Agent")
//                .headerValue("test")
        .build();

GenerateResult result = MemShellGenerator.generate(shellConfig, injectorConfig, godzillaConfig);

System.out.println("Injector Class Name: " + result.getInjectorClassName());
System.out.println("MemShell Class Name: " + result.getShellClassName());

System.out.println(result.getShellConfig());
System.out.println(result.getShellToolConfig());

byte[] agentJarBytes = ((JarPacker) Packers.AgentJar.getInstance()).packBytes(result);
Files.write(Paths.get("agent.jar"), agentJarBytes);
```
4. For a unified generation interface example, refer to [GeneratorController.java](../boot/src/main/java/com/reajason/javaweb/boot/controller/GeneratorController.java)

## Compatibility

Compatible with Java6 ~ Java8, Java9, Java11, Java17, Java21

### Middleware and Frameworks

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

### MemShell Functionality

- [x] [Godzilla](https://github.com/BeichenDream/Godzilla)
- [x] [Behinder](https://github.com/rebeyond/Behinder)
- [x] Command Execution
- [x] [Suo5](https://github.com/zema1/suo5)
- [x] [AntSword](https://github.com/AntSwordProject/antSword)
- [x] [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg)
- [x] Custom

### Packaging Methods

- [x] BASE64
- [x] GZIP BASE64
- [x] JSP
- [x] JSPX
- [x] JAR
- [x] BCEL
- [x] Built-in ScriptEngine, Rhino ScriptEngine
- [x] EL、SpEL、OGNL、Aviator、MVEL、JEXL、Groovy、JXPath、BeanShell
- [x] Velocity、Freemarker、JinJava
- [x] Native Deserialization（CB and CC）
- [x] Agent
- [x] XXL-JOB Executor
- [x] Hessian, Hessian2 Deserialization (XSLT gadget chain)
- [ ] JNDI
- [ ] JDBC Connection
- [ ] Other common deserialization

## Local Build

### Building from Source Code

> Suitable for developers who want to modify the code. Clone the repository locally and build the frontend and backend projects.

First, you need to download and install [bun](https://bun.sh/), a tool for building the frontend service.

1. Clone the project using Git:
```bash
git clone https://github.com/ReaJason/MemShellParty.git
```
2. Build the frontend project. After the build finishes, static resources will be automatically moved to the Spring Boot module.
```bash
cd MemShellParty/web

bun install

bun run build
```
3. Build the backend project. Ensure you are using a JDK 17 environment.
```bash
cd MemShellParty/boot

./gradlew :boot:bootjar -x test
```

After building, you can directly run the JAR file located at `MemShellParty/boot/build/libs/boot-*.jar` (the exact version might vary).

```bash
cd MemShellParty/boot

java -jar \
     --add-opens=java.base/java.util=ALL-UNNAMED \
     --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
     --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
     build/libs/boot-1.0.0.jar
```

Alternatively, you can build a Docker container from the built artifacts:

```bash
cd MemShellParty/boot

docker buildx build -t memshell-party:latest . --load

docker run -it -d --name memshell-party -p 8080:8080 memshell-party:latest
```

### Building with Dockerfile Directly

> Suitable for users who want to build with custom access paths, for example, when using NGINX as a reverse proxy ([#44](https://github.com/ReaJason/MemShellParty/issues/44)).

Download the [Dockerfile](./Dockerfile) from the project root.

- VERSION: Version information (arbitrary, suggest using the latest tag; used for frontend display).
- ROUTE_ROOT_PATH: Frontend root route configuration (e.g., /memshell-party).
- CONTEXT_PATH: Backend access prefix (e.g., /memshell-party).

```bash
# Basic build (defaults to root path "/")
docker buildx build \
    --build-arg VERSION=1.7.0 \
    -t memshell-party:latest . --load

# Run the basic image, access at http://127.0.0.1:8080
docker run -it -d -p 8080:8080 memshell-party:latest

# Build with custom access path (e.g., /memshell-party)
docker buildx build \
    --build-arg VERSION=1.7.0 \
    --build-arg ROUTE_ROOT_PATH=/memshell-party \
    --build-arg CONTEXT_PATH=/memshell-party \
    -t memshell-party:latest . --load
    
# Run the custom path image, access at http://127.0.0.1:8080/memshell-party
docker run -it -p 8080:8080 \
    -e BOOT_OPTS=--server.servlet.context-path=/memshell-party \
    memshell-party:latest
```

If you need to use NGINX as a reverse proxy, first build the container with a custom access path. Then configure NGINX similar to the following:

Ensure that the `location /memshell-party`、`ROUTE_ROOT_PATH=/memshell-party`、`CONTEXT_PATH=/memshell-party` and
`BOOT_OPTS=--server.servlet.context-path=/memshell-party` all use the same path.

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

## Contribute

> Any feedback or issue discussion you provide is a contribution to this project.

> It will be so nice if you want to contribute. 🎉

1. If you have strong Docker environment building skills, consider adding integration test cases related to specific CVEs. 
2. If you are skilled in writing memory shells, try adding support for a new type or target. 
3. If you have extensive practical experience, feel free to open issues with suggestions or improvements.

For project structure, build processes, and compilation details, please refer to [CONTRIBUTING.md](CONTRIBUTING.md)。

## Thanks

- [pen4uin/java-memshell-generator](https://github.com/pen4uin/java-memshell-generator)

### Let's start the party 🎉
