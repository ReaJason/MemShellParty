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
public class Tomcat7ContainerTest extends TomcatIntegrationTest {
    public static final String tomcat7ImageName = "tomcat:7.0.85-jre7";
    @Container
    public final static GenericContainer<?> tomcat = new GenericContainer<>(tomcat7ImageName)
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
