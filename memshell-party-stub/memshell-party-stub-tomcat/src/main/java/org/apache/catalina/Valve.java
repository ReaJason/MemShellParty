package org.apache.catalina;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * Tomcat {@code org.apache.catalina.Valve} 的生成期桩：Valve 类模板要实现它，生成引擎按字节解析
 * 模板父链时需要这份声明。方法集与 Tomcat 逐一对齐（模板覆写的就是这几个），多一个少一个都会让
 * 生成的字节码与真实 Tomcat 对不上。
 *
 * @author ReaJason
 * @since 2026/10/13
 */
public interface Valve {

    Valve getNext();

    void setNext(Valve valve);

    void backgroundProcess();

    void invoke(Request request, Response response) throws IOException, ServletException;

    boolean isAsyncSupported();
}
