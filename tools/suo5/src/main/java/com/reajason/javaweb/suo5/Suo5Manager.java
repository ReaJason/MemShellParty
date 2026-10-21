package com.reajason.javaweb.suo5;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * @author ReaJason
 * @since 2025/2/12
 */
public class Suo5Manager {

    public static final String suo5Command;

    private static final String READY_LINE = "test connection succeeded, tunnel is ready";
    private static final String RESPONSE_LINE = "test connection got response";

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
    }

    public static void main(String[] args) {
        System.out.println(suo5Command);
        boolean test = test("", "http://localhost:8082/app/test", "test");
        System.out.println(test);
    }

    public static boolean test(String shellTool, String targetUrl, String ua) {
        return test(shellTool, targetUrl, ua, null, -1);
    }

    /**
     * 真断言验证 suo5 隧道。
     *
     * <p>给了 tunnelTarget（容器内部视角的应用地址，一般是 127.0.0.1:exposedPort）时，
     * 用客户端隐藏的 {@code -T} 参数经隧道发一次真实 HTTP GET：
     * 进程退出码 0 且输出里有 "test connection got response" 才算通过
     * （客户端对非超时错误会宽容地退出 0，必须看输出行）。</p>
     *
     * <p>没给 tunnelTarget 时退化为等待隧道自测成功行（仅证明握手+协议层可用）。</p>
     */
    public static boolean test(String shellTool, String targetUrl, String ua, String tunnelTargetHost, int tunnelTargetPort) {
        int localPort = findFreePort();
        if (localPort < 0) {
            return false;
        }
        boolean withDataPlane = tunnelTargetHost != null && tunnelTargetPort > 0;
        List<String> command = new ArrayList<>(Arrays.asList(
                suo5Command, "-d", "-t", targetUrl,
                "-l", "127.0.0.1:" + localPort,
                "--timeout", "8", "-ua", ua, "-H", "Referer: " + targetUrl
        ));
        if (withDataPlane) {
            command.add("-T");
            command.add("http://" + tunnelTargetHost + ":" + tunnelTargetPort + "/");
        }
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Process process = null;
        try {
            StringBuilder output = new StringBuilder();
            process = processBuilder.start();
            Process finalProcess = process;
            executor.submit(() -> drainOutput(finalProcess, output));
            if (withDataPlane) {
                // -T 模式下进程必定自行退出：0=隧道通了且拿到响应，1=失败
                boolean exited = process.waitFor(25, TimeUnit.SECONDS);
                return exited && process.exitValue() == 0 && output.toString().contains(RESPONSE_LINE);
            }
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
            while (System.nanoTime() < deadline) {
                String snapshot = output.toString();
                if (snapshot.contains(READY_LINE)) {
                    return true;
                }
                if (snapshot.contains("FTAL") || snapshot.contains("[ERRO]") || !process.isAlive()) {
                    return false;
                }
                Thread.sleep(100);
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            if (process != null) {
                process.destroyForcibly();
            }
            executor.shutdownNow();
        }
    }

    private static void drainOutput(Process process, StringBuilder output) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
                synchronized (output) {
                    output.append(line).append('\n');
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static int findFreePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (Exception e) {
            return -1;
        }
    }
}
