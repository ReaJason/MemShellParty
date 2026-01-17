package com.reajason.javaweb.integration.memshell.struct2;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.integration.ContainerTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
@Testcontainers
public class Struct2ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.builder()
            .imageName("tomcat:8-jre8")
            .server(Server.Struct2)
            .warFile(ContainerTool.struct2WarFile)
            .warDeployPath("/usr/local/tomcat/webapps/app.war")
            .pidScript(ContainerTool.tomcatPid)
            .enableJspPackerTest(false)
            .targetJdkVersion(Opcodes.V1_8)
            .supportedShellTypes(List.of(ShellType.ACTION))
            .testPackers(List.of(Packers.ScriptEngine))
            .probeShellTypes(List.of(ShellType.ACTION))
            .build();

    static Network network = newNetwork();
    @Container
    public static final GenericContainer<?> python = buildPythonContainer(network);

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG, network);

    @Override
    protected ContainerTestConfig getConfig() {
        return CONFIG;
    }
}
