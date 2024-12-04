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
public class Tomcat8ContainerTest extends TomcatIntegrationTest {
    public static final String tomcat8ImageName = "tomcat:8-jre8";
    @Container
    public final static GenericContainer<?> tomcat = new GenericContainer<>(tomcat8ImageName)
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
