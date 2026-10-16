package com.reajason.javaweb.memshell.shelltool.antsword;

import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.ToolMapping;
import com.reajason.javaweb.memshell.spi.ShellToolMeta;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;

import org.kohsuke.MetaInfServices;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 3.0.0
 */
@MetaInfServices(ShellToolProvider.class)
@ShellToolMeta(name = ShellTool.AntSword, order = 60)
public class AntSwordShellToolProvider implements ShellToolProvider {

    @Override
    public ToolMapping getToolMapping() {
        return ToolMapping.builder()
                .addShellClass(SERVLET, "com.reajason.javaweb.memshell.shelltool.antsword.AntSwordServlet")
                .addShellClass(FILTER, "com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilter")
                .addShellClass(LISTENER, "com.reajason.javaweb.memshell.shelltool.antsword.AntSwordListener")
                .addShellClass(VALVE, "com.reajason.javaweb.memshell.shelltool.antsword.AntSwordValve")
                .addShellClass(PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.antsword.AntSword")
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.antsword.AntSwordInterceptor")
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.antsword.AntSwordControllerHandler")
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, "com.reajason.javaweb.memshell.shelltool.antsword.AntSword")
                .addShellClass(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.shelltool.antsword.AntSword")
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.shelltool.antsword.AntSword")
                .addShellClass(JETTY_AGENT_HANDLER, "com.reajason.javaweb.memshell.shelltool.antsword.AntSwordJettyHandler")
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, "com.reajason.javaweb.memshell.shelltool.antsword.AntSwordUndertowServletHandler")
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, "com.reajason.javaweb.memshell.shelltool.antsword.AntSword")
                .addShellClass(WAS_AGENT_FILTER_MANAGER, "com.reajason.javaweb.memshell.shelltool.antsword.AntSword")
                .addShellClass(ACTION, "com.reajason.javaweb.memshell.shelltool.antsword.AntSwordStruts2Action")
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return AntSwordConfig.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return AntSwordGenerator.class;
    }
}
