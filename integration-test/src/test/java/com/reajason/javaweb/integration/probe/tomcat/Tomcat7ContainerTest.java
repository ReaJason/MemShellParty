package com.reajason.javaweb.integration.probe.tomcat;

import com.reajason.javaweb.integration.probe.AbstractProbeContainerTest;
import com.reajason.javaweb.integration.probe.ProbeTestConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.junitpioneer.jupiter.RetryingTest;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
@Testcontainers
public class Tomcat7ContainerTest extends AbstractProbeContainerTest {

    private static final ProbeTestConfig CONFIG = ProbeTestConfig.tomcat("tomcat:7.0.85-jre7")
            .expectedJdkVersion("JRE|1.7.0_171|51")
            .targetJdkVersion(Opcodes.V1_7)
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

    @Override
    @RetryingTest(3)
    protected void testJDK() {
        doTestJDK();
    }

    // Tomcat 7 偶发新连接上 POST 表单参数解析不到（req.getParameter("data") 为 null），
    // 注入请求返回 500 导致内存马没装上；重试可恢复，同 testJDK 的处理。
    @Override
    @RetryingTest(3)
    protected void testFilterFirstInject() {
        super.testFilterFirstInject();
    }

    // 同样走 POST 表单注入，长结果分片断言对注入失败尤其敏感（-E/-C 头会整体缺失）
    @Override
    @RetryingTest(3)
    protected void testCommandReqHeaderResponseHeaderChunked() {
        super.testCommandReqHeaderResponseHeaderChunked();
    }

    // ScriptEngine 探测也经同一 POST 表单入口注入，可能遇到上述参数解析失败
    @Override
    @RetryingTest(3)
    protected void testScriptEngineReqHeaderResponseBody() {
        super.testScriptEngineReqHeaderResponseBody();
    }
}
