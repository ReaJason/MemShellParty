package org.apache.catalina.connector;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Tomcat {@code org.apache.catalina.connector.Response} 的生成期桩，规则同 {@link Request}：
 * 必须与真实 Tomcat 同为 class，方法声明在本类上才会生成 invokevirtual。
 *
 * @author ReaJason
 * @since 2026/10/13
 */
public abstract class Response implements HttpServletResponse {

    public ServletOutputStream getOutputStream() throws IOException {
        throw new UnsupportedOperationException();
    }

    public PrintWriter getWriter() throws IOException {
        throw new UnsupportedOperationException();
    }
}
