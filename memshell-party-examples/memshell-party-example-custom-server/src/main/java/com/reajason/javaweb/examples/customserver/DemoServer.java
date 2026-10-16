package com.reajason.javaweb.examples.customserver;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * 自定义 server：一个跑在 servlet 容器里的"应用内注入"实现。
 *
 * <p>与内置 Tomcat 注入器（从线程里挖 {@code StandardContext}，支持应用外注入）不同，
 * 本示例的注入器假设自己永远跑在应用内部（JSP / EL / 表达式注入的入口都在 webapp 里），
 * 找 {@code StandardContext} 只需从 TCCL 反射两步；注册部分与内置注入器一样走
 * {@code StandardContext} 私有反射 —— 公有 API 在 context 初始化后被 Tomcat 拒绝。
 *
 * <p>Jakarta 变体复用同一份 javax 模板，生成期由 JakartaPostProcessor 改名。
 *
 * @author ReaJason
 */
public class DemoServer extends AbstractServer {

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(FILTER, "com.reajason.javaweb.examples.customserver.DemoFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.examples.customserver.DemoFilterInjector")
                .addInjector(SERVLET, "com.reajason.javaweb.examples.customserver.DemoServletInjector")
                .addInjector(JAKARTA_SERVLET, "com.reajason.javaweb.examples.customserver.DemoServletInjector")
                .build();
    }
}
