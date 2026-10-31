package com.reajason.javaweb.integration;

import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.shelltool.command.CommandConfig;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.JarPackerConfig;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.utils.RandomUtils;
import lombok.extern.slf4j.Slf4j;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/** Verifies the persisted middleware jar, rather than only the running Agent transformer. */
@Slf4j
public final class AgentPersistenceAssertion {
    private static final Pattern ORIGINAL_JAR =
            Pattern.compile("MemShell Agent persisted ([^\\r\\n\\]|]+)(?:\\|#)?\\]*\\r?$", Pattern.MULTILINE);
    private static final Pattern BACKUP_JAR =
            Pattern.compile("Original jar backup: ([^\\r\\n\\]|]+)(?:\\|#)?\\]*\\r?$", Pattern.MULTILINE);
    private static final Pattern RESTORED_JAR =
            Pattern.compile("MemShell Agent restored ([^\\r\\n\\]|]+)(?:\\|#)?\\]*\\r?$", Pattern.MULTILINE);
    private static final OkHttpClient HTTP = new OkHttpClient.Builder()
            .connectTimeout(2, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build();

    private AgentPersistenceAssertion() {
    }

    public static void assertPersistence(ContainerTestConfig config, String shellType,
                                         GenericContainer<?> container) throws Exception {
        String packer = Packers.AgentJar;
        ShellToolConfig toolConfig = ShellAssertion.getShellToolConfig(shellType, ShellTool.Command, packer);
        MemShellResult result = ShellAssertion.generate(null, config.getServer(), config.getServerVersion(),
                shellType, ShellTool.Command, config.getTargetJdkVersion(), toolConfig, packer);
        String paramName = ((CommandConfig) toolConfig).getParamName();
        String marker = "PERSISTED_" + RandomUtils.randomAlphabetic(12);
        String command = "printf " + marker;
        String shellUrl = shellUrl(config, container);

        if (config.getAgentPersistReadyLog() != null) {
            awaitReady(config, container, Duration.ofMinutes(2), 0);
        }
        ResponseData baseline = execute(shellUrl, paramName, command);
        assertEquals(200, baseline.code, baseline.body);
        assertFalse(baseline.body.contains(marker), baseline.body);

        String containerAgentJar = "/agent-persistence-" + RandomUtils.randomAlphabetic(8) + ".jar";
        Path agentJar = Files.createTempFile("agent-persistence-", ".jar");
        try {
            byte[] bytes = ((JarPacker) PackerRegistry.getInstance().get(packer))
                    .packBytes(JarPackerConfig.from(result));
            Files.write(agentJar, bytes);
            container.copyFileToContainer(MountableFile.forHostPath(agentJar, 0100666), containerAgentJar);
        } finally {
            Files.deleteIfExists(agentJar);
        }

        PersistencePaths paths = null;
        boolean restored = false;
        try {
            int logOffset = container.getLogs().length();
            String pid = container.execInContainer("bash", "/fetch_pid.sh").getStdout().trim();
            Container.ExecResult attach = attachAgent(container, pid, containerAgentJar, "persist=true");
            log.info("persist attach stdout: {}\nstderr: {}", attach.getStdout(), attach.getStderr());
            assertEquals(0, attach.getExitCode(), attach.getStderr());
            assertTrue(attach.getStdout().contains("ATTACH_ACK")
                            || attach.getStdout().contains("JVM response code = 0"),
                    attach.getStdout());

            paths = awaitPersistencePaths(container, logOffset);
            Container.ExecResult backupExists = container.execInContainer("test", "-f", paths.backupJar);
            assertEquals(0, backupExists.getExitCode(), "Missing backup: " + paths.backupJar);

            ResponseData injected = execute(shellUrl, paramName, command);
            assertEquals(200, injected.code, injected.body);
            assertTrue(injected.body.contains(marker), injected.body);
            restartAndAwait(config, container);
            ResponseData afterRestart = execute(shellUrl(config, container), paramName, command);
            assertEquals(200, afterRestart.code, afterRestart.body);
            assertTrue(afterRestart.body.contains(marker),
                    "Persisted shell did not survive restart; original jar=" + paths.originalJar);

            restorePersistedJar(container, containerAgentJar, paths);
            restored = true;
            ResponseData restoredInPlace = execute(shellUrl(config, container), paramName, command);
            assertEquals(200, restoredInPlace.code, restoredInPlace.body);
            assertEquals(baseline.body, restoredInPlace.body,
                    "restore=true should remove the running transform without a restart");
            assertNotEquals(0, container.execInContainer("test", "-f", paths.backupJar).getExitCode(),
                    "restore=true should remove the backup: " + paths.backupJar);

            restartAndAwait(config, container);

            ResponseData restoredResponse = execute(shellUrl(config, container), paramName, command);
            assertEquals(200, restoredResponse.code, restoredResponse.body);
            assertEquals(baseline.body, restoredResponse.body, "Restored jar should not execute the persisted shell");
        } finally {
            if (paths != null && !restored) {
                try {
                    restoreAndRestart(config, container, paths);
                } catch (Exception | AssertionError cleanupError) {
                    log.error("Failed to restore persisted jar after test failure: {}", paths.originalJar, cleanupError);
                }
            }
        }
    }

    private static void restorePersistedJar(GenericContainer<?> container, String containerAgentJar,
                                            PersistencePaths paths) throws Exception {
        String pid = container.execInContainer("bash", "/fetch_pid.sh").getStdout().trim();
        int logOffset = container.getLogs().length();
        Container.ExecResult restore = attachAgent(container, pid, containerAgentJar, "restore=true");
        log.info("restore attach stdout: {}\nstderr: {}", restore.getStdout(), restore.getStderr());
        assertEquals(0, restore.getExitCode(), restore.getStderr());
        assertTrue(restore.getStdout().contains("ATTACH_ACK")
                        || restore.getStdout().contains("JVM response code = 0"),
                restore.getStdout());
        assertEquals(paths.originalJar, awaitRestoredJar(container, logOffset));
    }

    private static Container.ExecResult attachAgent(GenericContainer<?> container, String pid,
                                                     String containerAgentJar, String args) throws Exception {
        Container.ExecResult attach = container.execInContainer(
                "/jattach", pid, "load", "instrument", "false", containerAgentJar + "=" + args);
        if (attach.getExitCode() != 0
                && attach.getStderr().contains("Could not connect to socket: Connection refused")) {
            // Docker 重启保留 /tmp，旧 socket 会让 jattach 跳过新 JVM 的 attach 初始化。
            Container.ExecResult removeSocket = container.execInContainer(
                    "rm", "-f", "/tmp/.java_pid" + pid, "/tmp/.attach_pid" + pid);
            assertEquals(0, removeSocket.getExitCode(), removeSocket.getStderr());
            attach = container.execInContainer(
                    "/jattach", pid, "load", "instrument", "false", containerAgentJar + "=" + args);
        }
        return attach;
    }

    private static String awaitRestoredJar(GenericContainer<?> container, int logOffset) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (System.nanoTime() < deadline) {
            String restoredJar = lastMatch(RESTORED_JAR, logsSince(container, logOffset));
            if (restoredJar != null) {
                return restoredJar;
            }
            Thread.sleep(100);
        }
        String logs = logsSince(container, logOffset);
        String restoredJar = lastMatch(RESTORED_JAR, logs);
        assertNotNull(restoredJar, "Missing restored jar log:\n" + logs);
        return restoredJar;
    }

    private static PersistencePaths awaitPersistencePaths(GenericContainer<?> container, int logOffset) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (System.nanoTime() < deadline) {
            String logs = logsSince(container, logOffset);
            String originalJar = lastMatch(ORIGINAL_JAR, logs);
            String backupJar = lastMatch(BACKUP_JAR, logs);
            if (originalJar != null && backupJar != null
                    && container.execInContainer("test", "-f", backupJar).getExitCode() == 0) {
                return new PersistencePaths(originalJar, backupJar);
            }
            Thread.sleep(100);
        }
        return persistencePaths(logsSince(container, logOffset));
    }

    private static PersistencePaths persistencePaths(String logs) {
        String originalJar = lastMatch(ORIGINAL_JAR, logs);
        String backupJar = lastMatch(BACKUP_JAR, logs);
        assertNotNull(originalJar, "Missing persisted jar log:\n" + logs);
        assertNotNull(backupJar, "Missing backup jar log:\n" + logs);
        return new PersistencePaths(originalJar, backupJar);
    }

    private static String logsSince(GenericContainer<?> container, int logOffset) {
        String logs = container.getLogs();
        return logs.substring(Math.min(logOffset, logs.length()));
    }

    private static String lastMatch(Pattern pattern, String value) {
        Matcher matcher = pattern.matcher(value);
        String result = null;
        while (matcher.find()) {
            result = matcher.group(1).trim();
        }
        return result;
    }

    private static void restoreAndRestart(ContainerTestConfig config, GenericContainer<?> container,
                                          PersistencePaths paths) throws Exception {
        Path cleanBackup = Files.createTempFile("middleware-clean-backup-", ".jar");
        try {
            container.copyFileFromContainer(paths.backupJar, cleanBackup.toString());
            int logOffset = container.getLogs().length();
            stopServer(config, container);
            container.copyFileToContainer(MountableFile.forHostPath(cleanBackup, 0100644), paths.originalJar);
            startServer(config, container);
            awaitReady(config, container, Duration.ofMinutes(2), logOffset);
            Container.ExecResult removeBackup = container.execInContainer("rm", paths.backupJar);
            assertEquals(0, removeBackup.getExitCode(), removeBackup.getStderr());
        } finally {
            Files.deleteIfExists(cleanBackup);
        }
    }

    private static void restartAndAwait(ContainerTestConfig config, GenericContainer<?> container) throws Exception {
        int logOffset = container.getLogs().length();
        stopServer(config, container);
        startServer(config, container);
        awaitReady(config, container, Duration.ofMinutes(2), logOffset);
    }

    private static void stopServer(ContainerTestConfig config, GenericContainer<?> container) throws Exception {
        if (config.getAgentPersistStopCommand() != null) {
            executeCommand(container, config.getAgentPersistStopCommand());
        } else if (config.isAgentPersistForceStop()) {
            container.getDockerClient().killContainerCmd(container.getContainerId()).exec();
        } else {
            container.getDockerClient().stopContainerCmd(container.getContainerId()).exec();
        }
    }

    private static void startServer(ContainerTestConfig config, GenericContainer<?> container) throws Exception {
        if (config.getAgentPersistStartCommand() != null) {
            executeCommand(container, config.getAgentPersistStartCommand());
        } else {
            container.getDockerClient().startContainerCmd(container.getContainerId()).exec();
        }
    }

    private static void executeCommand(GenericContainer<?> container, String command) throws Exception {
        Container.ExecResult result = container.execInContainer("sh", "-c", command);
        assertEquals(0, result.getExitCode(),
                command + "\nstdout:\n" + result.getStdout() + "\nstderr:\n" + result.getStderr());
    }

    private static void awaitReady(ContainerTestConfig config, GenericContainer<?> container,
                                   Duration timeout, int logOffset) throws Exception {
        String healthPath = path(config.getHealthCheckPath());
        String readyLog = config.getAgentPersistReadyLog();
        long deadline = System.nanoTime() + timeout.toNanos();
        Throwable lastFailure = null;
        while (System.nanoTime() < deadline) {
            try {
                if (readyLog != null) {
                    String restartLogs = logsSince(container, logOffset);
                    if (!restartLogs.contains(readyLog)) {
                        lastFailure = new IOException("Missing readiness log after restart: " + readyLog);
                        Thread.sleep(500);
                        continue;
                    }
                }
                String healthUrl = ContainerTool.getRootUrl(container, config.getExposedPort()) + healthPath;
                ResponseData response = execute(healthUrl, null, null);
                if (response.code == 200) {
                    long readyDelayMillis = config.getAgentPersistReadyDelayMillis();
                    if (readyDelayMillis > 0) {
                        Thread.sleep(readyDelayMillis);
                    }
                    return;
                }
                lastFailure = new IOException("HTTP " + response.code + ": " + response.body);
            } catch (IOException | RuntimeException e) {
                lastFailure = e;
            }
            Thread.sleep(500);
        }
        throw new AssertionError("Container did not become ready on port "
                + config.getExposedPort() + healthPath, lastFailure);
    }

    private static ResponseData execute(String url, String paramName, String command) throws IOException {
        HttpUrl parsed = Objects.requireNonNull(HttpUrl.parse(url));
        if (paramName != null) {
            parsed = parsed.newBuilder().addQueryParameter(paramName, command).build();
        }
        Request request = new Request.Builder().url(parsed).get().build();
        try (Response response = HTTP.newCall(request).execute()) {
            return new ResponseData(response.code(), response.body().string());
        }
    }

    private static String shellUrl(ContainerTestConfig config, GenericContainer<?> container) {
        return ContainerTool.getRootUrl(container, config.getExposedPort()) + path(config.getContextPath()) + "/test";
    }

    private static String path(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return value.startsWith("/") ? value : "/" + value;
    }

    private static final class PersistencePaths {
        private final String originalJar;
        private final String backupJar;

        private PersistencePaths(String originalJar, String backupJar) {
            this.originalJar = originalJar;
            this.backupJar = backupJar;
        }
    }

    private static final class ResponseData {
        private final int code;
        private final String body;

        private ResponseData(int code, String body) {
            this.code = code;
            this.body = body;
        }
    }
}
