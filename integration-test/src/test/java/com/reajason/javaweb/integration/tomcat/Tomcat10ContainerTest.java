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
public class Tomcat10ContainerTest extends TomcatIntegrationTest {
    public static final String tomcat10ImageName = "tomcat:10.1-jre11";
    @Container
    public final static GenericContainer<?> tomcat = new GenericContainer<>(tomcat10ImageName)
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
