package com.reajason.javaweb.probe.payload;

import net.bytebuddy.asm.Advice;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * HTTP 服务类型识别，主要识别 Servlet 容器实现，例如 WildFly 识别为 Undertow，Payara 识别为 GlassFish
 * 很多国产中间件都是基于 GlassFish 改的，都会识别为 GlassFish
 * 额外需要注意：
 * 1. 不会识别 SpringWebMVC Struct2 这种框架，只识别其提供 HTTP 服务的 Servlet 容器类型
 * 2. 识别的顺序很重要，部分类型的识别单独拿出来是不准确的，没有测试的情况下，不要以下的 if 判断顺序
 *
 * @author ReaJason
 * @since 2025/7/26
 */
public class ServerProbe {

    @Advice.OnMethodExit
    public static String exit(@Advice.Return(readOnly = false) String ret) {
        Collection<StackTraceElement[]> stackTraceElements = Thread.getAllStackTraces().values();
        Set<String> classNames = new HashSet<>();
        for (StackTraceElement[] stackTraceElement : stackTraceElements) {
            for (StackTraceElement traceElement : stackTraceElement) {
                classNames.add(traceElement.getClassName());
            }
        }
        if (System.getProperty("jetty.home") != null
                || classNames.contains("org.eclipse.jetty.util.thread.QueuedThreadPool")) {
            return ret = "Jetty";
        }
        if (classNames.contains("io.undertow.server.Connectors")) {
            return ret = "Undertow";
        }
        if (System.getProperty("com.cvicse.inforsuite.base.dir") != null) {
            return ret = "InforSuite";
        }
        if (System.getProperty("com.apusic.home") != null) {
            return ret = "Apusic";
        }
        if (System.getProperty("bes.home") != null
                && classNames.contains("com.bes.enterprise.web.util.threads.WorkQueue")) {
            return ret = "BES";
        }
        if (System.getProperty("tongweb.home") != null) {
            return ret = "TongWeb";
        }
        if (System.getProperty("weblogic.home") != null) {
            return ret = "WebLogic";
        }
        if (System.getProperty("was.install.root") != null
                || System.getProperty("wlp.install.dir") != null) {
            return ret = "WebSphere";
        }
        if (System.getProperty("resin.home") != null) {
            return ret = "Resin";
        }
        if (classNames.contains("org.springframework.boot.web.embedded.netty.NettyWebServer$1")) {
            return ret = "SpringWebFlux";
        }
        if (System.getProperty("AS_INSTALL") != null) {
            return ret = "GlassFish";
        }
        if (System.getProperty("jboss.home.dir") != null
                && classNames.contains("org.apache.tomcat.util.net.JIoEndpoint$Acceptor")) {
            return ret = "JBoss";
        }
        if (System.getProperty("catalina.home") != null
                || classNames.contains("org.apache.tomcat.util.threads.TaskQueue")) {
            return ret = "Tomcat";
        }
        return ret = "Unknown";
    }

    @Override
    public String toString() {
        return ServerProbe.exit(super.toString());
    }
}
