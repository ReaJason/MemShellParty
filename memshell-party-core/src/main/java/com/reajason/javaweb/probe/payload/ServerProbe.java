package com.reajason.javaweb.probe.payload;

import net.bytebuddy.asm.Advice;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * HTTP 服务类型识别，主要识别 Servlet 容器实现，例如 WildFly 识别为 Undertow，Payara 识别为 GlassFish
 * 很多国产中间件都是基于 GlassFish 改的，都会识别为 GlassFish
 * 额外需要注意：
 * 1. 会额外识别 SpringWebMvc、Struts2 框架，命中时以框架前缀拼接到容器类型前，例如 SpringWebMvc,Tomcat、Struts2,Tomcat
 * 2. 识别的顺序很重要，部分类型的识别单独拿出来是不准确的，没有测试的情况下，不要改动以下的 if 判断顺序
 *
 * @author ReaJason
 * @since 2025/7/26
 */
public class ServerProbe {

    @Advice.OnMethodExit
    public static String exit(@Advice.Return(readOnly = false) String ret) {
        Collection<StackTraceElement[]> stackTraceElements = Thread.getAllStackTraces().values();
        Set<String> classNames = new HashSet<>();
        boolean struts2 = false;
        for (StackTraceElement[] stackTraceElement : stackTraceElements) {
            for (StackTraceElement traceElement : stackTraceElement) {
                String className = traceElement.getClassName();
                classNames.add(className);
                // Struts2 的过滤器、Dispatcher、ActionInvocation 都在 org.apache.struts2 包下，
                // 用包名前缀识别，避免为每个版本的类名单独塞字符串常量撑大探测马字节码
                if (className.startsWith("org.apache.struts2.")) {
                    struts2 = true;
                }
            }
        }
        // 探测马在请求处理线程内执行：SpringWebMvc 应用的线程栈中会出现 DispatcherServlet
        String framework = "";
        if (classNames.contains("org.springframework.web.servlet.DispatcherServlet")) {
            framework = "SpringWebMvc,";
        }
        if (struts2) {
            framework += "Struts2,";
        }
        if (classNames.contains("org.mortbay.http.HttpConnection")
                || classNames.contains("org.mortbay.http.HttpServer")) {
            return ret = framework + "Jetty5";
        }
        if (System.getProperty("jetty.home") != null
                || classNames.contains("org.eclipse.jetty.util.thread.QueuedThreadPool")) {
            return ret = framework + "Jetty";
        }
        if (classNames.contains("io.undertow.server.Connectors")) {
            return ret = framework + "Undertow";
        }
        if (System.getProperty("com.cvicse.inforsuite.base.dir") != null) {
            return ret = framework + "InforSuite";
        }
        if (System.getProperty("com.apusic.home") != null) {
            return ret = framework + "Apusic";
        }
        if ((System.getProperty("bes.home") != null || System.getProperty("bes.base") != null)
                && classNames.contains("com.bes.enterprise.web.util.threads.WorkQueue")) {
            return ret = framework + "BES";
        }
        if (System.getProperty("tongweb.home") != null) {
            return ret = framework + "TongWeb";
        }
        if (System.getProperty("weblogic.home") != null) {
            return ret = framework + "WebLogic";
        }
        if (System.getProperty("was.install.root") != null
                || System.getProperty("wlp.install.dir") != null) {
            return ret = framework + "WebSphere";
        }
        if (System.getProperty("resin.home") != null
                && classNames.contains("com.caucho.server.dispatch.ServletInvocation")) {
            return ret = framework + "Resin";
        }
        if (System.getProperty("resin.home") != null
                && (classNames.contains("com.caucho.server.http.HttpRequest")
                || classNames.contains("com.caucho.server.http.ServletServer"))) {
            return ret = framework + "Resin2";
        }
        if (classNames.contains("org.springframework.boot.web.embedded.netty.NettyWebServer$1")
                || classNames.contains("org.springframework.boot.reactor.netty.NettyWebServer$1")) {
            return ret = "SpringWebFlux";
        }
        if (System.getProperty("AS_INSTALL") != null
                || System.getProperty("com.sun.aas.installRoot") != null
                || System.getProperty("glassfish.version") != null) {
            return ret = framework + "GlassFish";
        }
        if (System.getProperty("jboss.home.dir") != null
                && classNames.contains("org.apache.tomcat.util.net.JIoEndpoint$Acceptor")) {
            return ret = framework + "JBoss";
        }
        if (System.getProperty("catalina.home") != null
                || classNames.contains("org.apache.tomcat.util.threads.TaskQueue")) {
            return ret = framework + "Tomcat";
        }
        return ret = framework + "Unknown";
    }

    @Override
    public String toString() {
        return ServerProbe.exit(super.toString());
    }
}
