package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.buddy.LdcReAssignVisitorWrapper;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.Constants;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.Suo5Config;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/2/12
 */
public class Suo5Generator {
    private final ShellConfig shellConfig;
    private final Suo5Config suo5Config;

    public Suo5Generator(ShellConfig shellConfig, Suo5Config suo5Config) {
        this.shellConfig = shellConfig;
        this.suo5Config = suo5Config;
    }

    public DynamicType.Builder<?> getBuilder() {
        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(suo5Config.getShellClass())
                .name(suo5Config.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()));

        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        if (shellConfig.getShellType().startsWith(Constants.AGENT)) {
            builder = builder.visit(
                    new LdcReAssignVisitorWrapper(Map.of(
                            "headerName", suo5Config.getHeaderName(),
                            "headerValue", suo5Config.getHeaderValue()
                    ))
            );
        } else {
            builder = builder
                    .field(named("headerName")).value(suo5Config.getHeaderName())
                    .field(named("headerValue")).value(suo5Config.getHeaderValue());
        }
        return builder;
    }

    public byte[] getBytes() {
        DynamicType.Builder<?> builder = getBuilder();
        try (DynamicType.Unloaded<?> make = builder.make()) {
            return make.getBytes();
        }
    }
}
