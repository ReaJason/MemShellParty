package org.apache.catalina.connector;

import javax.servlet.ServletContext;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Enumeration;

/**
 * Tomcat {@code org.apache.catalina.connector.Request} 的生成期桩。它必须是 <b>class</b> 而不是
 * interface：模板里 {@code request.getHeader(..)} 编译成 invokevirtual 还是 invokeinterface 由这里
 * 的类型种类决定，跟真实 Tomcat 不一致会在目标容器上抛 IncompatibleClassChangeError。
 * <p>
 * 同理，方法声明在<b>本类</b>还是继承自 {@link HttpServletRequest} 也影响生成的指令 —— 只声明模板真正
 * 调用到的、且真实 Tomcat 声明在本类上的方法（新增模板调用时照 javap 的真实签名往这里补）。
 * <p>
 * 抽象类：桩永远不会被实例化，也就不必把 HttpServletRequest 的其余方法补齐。
 *
 * @author ReaJason
 * @since 2026/10/13
 */
public abstract class Request implements HttpServletRequest {

    public String getHeader(String name) {
        throw new UnsupportedOperationException();
    }

    public Enumeration<String> getHeaderNames() {
        throw new UnsupportedOperationException();
    }

    public String getParameter(String name) {
        throw new UnsupportedOperationException();
    }

    public String getMethod() {
        throw new UnsupportedOperationException();
    }

    public String getContentType() {
        throw new UnsupportedOperationException();
    }

    public String getPathInfo() {
        throw new UnsupportedOperationException();
    }

    public String getServletPath() {
        throw new UnsupportedOperationException();
    }

    public ServletInputStream getInputStream() throws IOException {
        throw new UnsupportedOperationException();
    }

    public BufferedReader getReader() throws IOException {
        throw new UnsupportedOperationException();
    }

    public HttpSession getSession() {
        throw new UnsupportedOperationException();
    }

    public ServletContext getServletContext() {
        throw new UnsupportedOperationException();
    }

    public Response getResponse() {
        throw new UnsupportedOperationException();
    }
}
