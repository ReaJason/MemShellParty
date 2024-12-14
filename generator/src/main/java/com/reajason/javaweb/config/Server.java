package com.reajason.javaweb.config;

import com.reajason.javaweb.memsell.AbstractShell;
import com.reajason.javaweb.memsell.glassfish.GlassFishShell;
import com.reajason.javaweb.memsell.jboss.JbossShell;
import com.reajason.javaweb.memsell.jetty.JettyShell;
import com.reajason.javaweb.memsell.resin.ResinShell;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;
import com.reajason.javaweb.memsell.undertow.UndertowShell;
import lombok.Getter;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
@Getter
public enum Server {
    /**
     * Tomcat 中间件
     */
    Tomcat(new TomcatShell()),
    /**
     * Jetty 中间件
     */
    Jetty(new JettyShell()),
    /**
     * JBoss AS 中间件, JBoss 6.4-EAP 也使用的当前方式 <a href="https://jbossas.jboss.org/downloads">JBoss AS</a>
     */
    JBoss(new JbossShell()),
    /**
     * Undertow，对应是 Wildfly 以及 JBoss EAP，也有可能是 SpringBoot 用的
     * <a href="https://developers.redhat.com/products/eap/download">JBossEAP</a>
     */
    Undertow(new UndertowShell()),

    /**
     * SpringMVC 框架
     */
    SpringMVC(null),

    /**
     * Spring Webflux 框架
     */
    SpringWebflux(null),

    /**
     * WebSphere 中间件
     */
    WebSphere(null),

    /**
     * WebLogic 中间件
     */
    WebLogic(null),

    /**
     * Resin 中间件, <a href="https://caucho.com/products/resin/download">Resin</a>
     */
    Resin(new ResinShell()),

    /**
     * GlassFish 中间件
     */
    GlassFish(new GlassFishShell()),

    /**
     * 宝兰德中间件
     */
    Bes(null),

    /**
     * 东方通中间件
     */
    Tongweb(null),

    /**
     * 金蝶天燕中间件
     */
    Apusic(null),
    ;

    private final AbstractShell shell;

    Server(AbstractShell shell) {
        this.shell = shell;
    }
}