package com.reajason.javaweb.integration.probe.websphere7;

import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
@Testcontainers
public class WebSphere700ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.websphere(
                    "reajason/websphere:7.0.0.21",
                    "/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/monitoredDeployableApps/servers/server1/app.war")
            .expectedJdkVersion("JDK|1.6.0|50")
            .targetJdkVersion(Opcodes.V1_6)
            .supportsCommand(false)
            .supportsBytecode(false)
            // WAS7 的 SRTServletRequest/Response 只被当前处理线程的栈引用；从 Thread 对象
            // 出发遍历完整对象图（含 thread locals、静态字段、线程组，共 416k 对象）也
            // 找不到任何 Servlet 请求/响应，通用 Unknown writer 无法定位。WAS 请显式选 WebSphere。
            .supportsUnknownProbe(false)
            .waitStrategy(Wait.forHttp("/app/").forPort(9080).withStartupTimeout(Duration.ofMinutes(5)))
            .build();

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG);

    @Override
    protected ProbeTestConfig getConfig() {
        return CONFIG;
    }

    @Override
    protected GenericContainer<?> getContainer() {
        return container;
    }
}
