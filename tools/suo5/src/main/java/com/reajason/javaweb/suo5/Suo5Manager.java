package com.reajason.javaweb.suo5;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.*;

/**
 * @author ReaJason
 * @since 2025/2/12
 */
public class Suo5Manager {

    public static final String suo5Command;
    public static final String suo5v2Command;

    static {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        boolean isMac = os.contains("mac") || os.contains("darwin");
        boolean isArm = arch.contains("arm") || arch.contains("aarch64");

        String osType = isMac ? "darwin" : "linux";
        String osArch = isArm ? "arm64" : "amd64";
        Path pwd = Paths.get(System.getProperty("user.dir"));
        if (!pwd.endsWith("MemShellParty")) {
            pwd = pwd.getParent();
        }
        suo5Command = pwd.resolve(Paths.get("assets", "suo5", "suo5-" + osType + "-" + osArch)).toAbsolutePath().toString();
        suo5v2Command = pwd.resolve(Paths.get("assets", "suo5", "suo5v2-" + osType + "-" + osArch)).toAbsolutePath().toString();
    }

    public static void main(String[] args) {
        System.out.println(suo5Command);
        boolean test = test("", "http://localhost:8082/app/test", "test");
        System.out.println(test);
    }

    public static boolean test(String shellTool, String targetUrl, String ua) {
        String command = shellTool.endsWith("v2") ? suo5v2Command : suo5Command;
        ProcessBuilder processBuilder = new ProcessBuilder(
                command, "-debug", "-t", targetUrl, "--timeout", "8", "-ua", ua, "-H", "Referer: " + targetUrl
        );
        processBuilder.redirectErrorStream(true);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Process process = processBuilder.start();

            Future<Boolean> future = executor.submit(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.out.println(line);
                        if (line.contains("FTAL")) {
                            process.destroy();
                            return false;
                        }
                        if (line.contains("congratulations!")) {
                            process.destroy();
                            return true;
                        }
                    }
                    return false;
                }
            });
            try {
                return future.get(10, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                process.destroy();
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            executor.shutdownNow();
        }
    }
}