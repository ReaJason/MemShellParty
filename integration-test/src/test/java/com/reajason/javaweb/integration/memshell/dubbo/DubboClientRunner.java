package com.reajason.javaweb.integration.memshell.dubbo;

import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class DubboClientRunner {

    private DubboClientRunner() {
    }

    static String loadBytes(String clientKind, String url, String base64) {
        return run(clientKind, "load-bytes", url, base64);
    }

    static String runCommand(String clientKind, String url, String interfaceName, String command) {
        return run(clientKind, "run-command", url, interfaceName, command);
    }

    @SneakyThrows
    private static String run(String clientKind, String... args) {
        List<String> command = new ArrayList<String>();
        String javaExecutable = javaExecutable(clientKind);
        command.add(javaExecutable);
        if (supportsAddOpens(javaExecutable)) {
            command.add("--add-opens=java.base/java.lang=ALL-UNNAMED");
            command.add("--add-opens=java.base/java.math=ALL-UNNAMED");
        }
        command.add("-cp");
        command.add(clientClasspath(clientKind));
        command.add(mainClass(clientKind));
        for (String arg : args) {
            command.add(arg);
        }

        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        copy(process.getInputStream(), output);
        int exitCode = process.waitFor();
        String rendered = output.toString(StandardCharsets.UTF_8).trim();
        if (exitCode != 0) {
            throw new IllegalStateException("Dubbo client failed with exit code " + exitCode + "\n" + rendered);
        }
        return rendered;
    }

    private static String clientClasspath(String clientKind) {
        String property = System.getProperty("dubbo." + clientKind + ".client.classpath");
        if (isBlank(property)) {
            throw new IllegalStateException("missing dubbo." + clientKind + ".client.classpath system property");
        }
        return property;
    }

    private static String mainClass(String clientKind) {
        if ("alibaba".equals(clientKind)) {
            return "io.github.reajason.dubbo.fixture.client.alibaba.AlibabaDubboClient";
        }
        if ("apache".equals(clientKind)) {
            return "io.github.reajason.dubbo.fixture.client.apache.ApacheDubboClient";
        }
        throw new IllegalArgumentException("unsupported client kind: " + clientKind);
    }

    private static String javaExecutable(String clientKind) {
        if (!"alibaba".equals(clientKind)) {
            return "java";
        }
        String java8Home = System.getenv("JAVA8_HOME");
        if (isBlank(java8Home)) {
            java8Home = System.getProperty("java8.home");
        }
        if (isBlank(java8Home)) {
            return "java";
        }
        return java8Home + "/bin/java";
    }

    private static boolean supportsAddOpens(String javaExecutable) throws java.io.IOException, InterruptedException {
        Process process = new ProcessBuilder(javaExecutable, "-version")
                .redirectErrorStream(true)
                .start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        copy(process.getInputStream(), output);
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            return true;
        }
        return majorVersion(output.toString(StandardCharsets.UTF_8)) >= 9;
    }

    private static int majorVersion(String versionOutput) {
        Matcher matcher = Pattern.compile("version \"([^\"]+)\"").matcher(versionOutput);
        if (!matcher.find()) {
            return 9;
        }
        String version = matcher.group(1);
        if (version.startsWith("1.")) {
            int dot = version.indexOf('.', 2);
            return leadingInteger(dot < 0 ? version.substring(2) : version.substring(2, dot));
        }
        int dot = version.indexOf('.');
        return leadingInteger(dot < 0 ? version : version.substring(0, dot));
    }

    private static int leadingInteger(String value) {
        Matcher matcher = Pattern.compile("^(\\d+)").matcher(value);
        return matcher.find() ? Integer.parseInt(matcher.group(1)) : 9;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static void copy(InputStream inputStream, ByteArrayOutputStream outputStream) throws java.io.IOException {
        byte[] buffer = new byte[4096];
        int read;
        while ((read = inputStream.read(buffer)) >= 0) {
            outputStream.write(buffer, 0, read);
        }
    }
}
