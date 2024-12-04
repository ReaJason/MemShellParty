package com.reajason.javaweb.integration.tomcat;

import com.reajason.javaweb.memsell.packer.Packer;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
public class Tomcat11ContainerTest extends TomcatIntegrationTest {
    public static final String tomcat11ImageName = "tomcat:11.0-jre17";
    @Container
    public final static GenericContainer<?> tomcat = new GenericContainer<>(tomcat11ImageName)
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
