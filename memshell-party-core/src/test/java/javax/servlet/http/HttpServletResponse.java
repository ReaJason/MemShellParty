package javax.servlet.http;

/**
 * 测试桩：让 UnknownWriter 在没有容器的测试 JVM 里也能按名字解析到 Servlet API
 *
 * @author ReaJason
 */
public interface HttpServletResponse {
    Object getOutputStream();

    Object getWriter();

    void setHeader(String name, String value);

    boolean isCommitted();
}
