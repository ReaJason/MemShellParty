package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.memshell.*;
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
    JBossAS(new JbossShell()),
    JBossEAP6(new JbossShell()),
    /**
     * Undertow，对应是 Wildfly 以及 JBoss EAP，也有可能是 SpringBoot 用的
     * <a href="https://developers.redhat.com/products/eap/download">JBossEAP</a>
     */
    Undertow(new UndertowShell()),
    JBossEAP7(new UndertowShell()),
    WildFly(new UndertowShell()),

    /**
     * SpringMVC 框架
     */
    SpringWebMvc(new SpringWebMvcShell()),

    /**
     * Spring WebFlux 框架
     */
    SpringWebFlux(new SpringWebFluxShell()),

    /**
     * WebSphere 中间件
     */
    WebSphere(new WebSphereShell()),

    /**
     * WebLogic 中间件
     */
    WebLogic(new WebLogicShell()),

    /**
     * Resin 中间件, <a href="https://caucho.com/products/resin/download">Resin</a>
     */
    Resin(new ResinShell()),

    /**
     * GlassFish 中间件
     */
    GlassFish(new GlassFishShell()),
    Payara(new GlassFishShell()),

    /**
     * 宝兰德中间件
     */
    BES(new BesShell()),

    /**
     * 东方通中间件
     */
    TongWeb6(new TongWeb6Shell()),
    TongWeb7(new TongWeb7Shell()),

    /**
     * 金蝶天燕中间件
     */
    Apusic(new ApusicShell()),

    /**
     * 中创中间件
     */
    InforSuite(new InforSuiteShell()),
    ;

    private final AbstractShell shell;

    Server(AbstractShell shell) {
        this.shell = shell;
    }
}