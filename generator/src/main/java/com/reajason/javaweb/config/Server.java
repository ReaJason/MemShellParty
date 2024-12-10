package com.reajason.javaweb.config;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
public enum Server {
    /**
     * Tomcat 中间件
     */
    TOMCAT,
    /**
     * Jetty 中间件
     */
    JETTY,
    /**
     * JBoss AS 中间件, JBoss 6.4-EAP 也使用的当前方式 <a href="https://jbossas.jboss.org/downloads">JBoss AS</a>
     */
    JBOSS,
    /**
     * Undertow，对应是 Wildfly 以及 JBoss EAP，也有可能是 SpringBoot 用的
     * <a href="https://developers.redhat.com/products/eap/download">JBossEAP</a>
     */
    UNDERTOW,

    /**
     * SpringMVC 框架
     */
    SPRING_MVC,

    /**
     * Spring Webflux 框架
     */
    SPRING_WEBFLUX,

    /**
     * WebSphere 中间件
     */
    WEBSPHERE,

    /**
     * WebLogic 中间件
     */
    WEBLOGIC,

    /**
     * Resin 中间件
     */
    RESIN,

    /**
     * Glassfish 中间件
     */
    GLASSFISH,

    /**
     * 宝兰德中间件
     */
    BES,

    /**
     * 东方通中间件
     */
    TONGWEB,

    /**
     * 金蝶天燕中间件
     */
    APUSIC
}