## 如何使用自定义内存马功能

MemShellParty 参考 JMG 使用注入器和内存马分离的方式进行的内存马注入，注入的伪代码如下：

```java
Object context = getContext();
Object shell = defineClass(getShellBase64Str());

inject(context, shell);
```

自定义内存马就是开放 getShellBase64Str 的修改，通过生成界面传入内存马的 base64 或 class 文件来实现。

注入器的选择，在通过生成界面选完目标服务和挂载类型就已经确认好了，无法自定义。

### 实现参考

1. Servlets 相关内存马使用 javax.servlet 即可，当挂载类型选为 Jakarta 开头，在生成时会自动将 javax 改为
   jakarta，无须重复实现。
2. Listener 内存马生成时，通过 request 对象获取 response 方法会自动将不同的中间件实现填充到 getResponseFromRequest
   方法上，因此推荐按参考实现一样使用空实现，额外需要注意 getResponseFromRequest 中的 request 请求参数声明必须为 Object。
3. Valve 内存马使用 Tomcat Valve 的包名 (`org.apache.catalina.`) 即可，当选中 BES/TongWeb 等会自动改为其特有的包名前缀，无须重复实现。
4. Agent 内存马推荐使用 `Thread.currentThread().getContextClassLoader()` 进行反射调用所需的工具类，因为 Agent
   内存马类会放进所增强类的 ClassLoader 中，部分中间件会存在模块隔离，无法直接使用部分类，例如 `java.util.Base64`、
   `javax.crypto.Cipher`。

| 挂载类型                                                     | 参考实现                                                                                                                                                                                                |
|----------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Servlet/JakartaServlet                                   | [GodzillaServlet](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaServlet.java)                               |
| Filter/JakartaFilter                                     | [GodzillaFilter](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaFilter.java)                                 |
| Listener/JakartaListener                                 | [GodzillaListener](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaListener.java)                             |
| Valve/JakartaValve                                       | [GodzillaValve](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaValve.java)                                   |
| ProxyValve/JakartaProxyValve                             | [Godzilla](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/Godzilla.java)                                             |
| WebSocket/JakartaWebSocket                               | [GodzillaWebSocket](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaWebSocket.java)                           |
| (SpringWebMVC)Interceptor/JakartaInterceptor             | [GodzillaInterceptor](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaInterceptor.java)                       |
| (SpringWebMVC)ControllerHandler/JakartaControllerHandler | [GodzillaControllerHandler](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaControllerHandler.java)           |
| (SpringWebFlux)WebFilter                                 | [GodzillaWebFilter](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaWebFilter.java)                           |
| (SpringWebFlux)HandlerMethod                             | [GodzillaHandlerMethod](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaHandlerMethod.java)                   |
| (SpringWebFlux)HandlerFunction                           | [GodzillaHandlerFunction](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaHandlerFunction.java)               |
| NettyHandler                                             | [GodzillaNettyHandler](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaNettyHandler.java)                     |
| AgentFilterChain/AgentContextValve                       | [Godzilla](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/Godzilla.java)                                             |
| (SpringWebMVC)AgentFrameworkServlet                      | [Godzilla](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/Godzilla.java)                                             |
| (Jetty)AgentHandler                                      | [GodzillaJettyHandler](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaJettyHandler.java)                     |
| (WAS)AgentFilterManager                                  | [Godzilla](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/Godzilla.java)                                             |
| (WebLogic)AgentServletContext                            | [Godzilla](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/Godzilla.java)                                             |
| (Undertow)AgentServletHandler                            | [GodzillaUndertowServletHandler](https://github.com/ReaJason/MemShellParty/blob/master/memshell/src/main/java/com/reajason/javaweb/memshell/shelltool/godzilla/GodzillaUndertowServletHandler.java) |

### 参考步骤

1. 执行 `git clone https://github.com/ReaJason/MemShellParty.git` 下载当前项目到本地
2. 在 memshell/src/main/java/com/reajason/javaweb/memshell/shelltool 创建 custom 目录进行自定义内存马的编写
3. 执行 `./gradlew :memshell:compileJava` 或 `.\gradlew.bat :memshell:compileJava`
4. 在 memshell/build/classes/java/main/com/reajason/javaweb/memshell/shelltool/custom 下可以找到编译好的类文件
5. 在生成界面，选择目标服务 - Custom - 挂载类型，上传 class 文件，选择打包方式并生成