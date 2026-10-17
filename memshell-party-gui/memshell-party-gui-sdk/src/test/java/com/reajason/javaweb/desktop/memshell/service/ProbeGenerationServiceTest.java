package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.DesktopProbeShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.ProbeShellFormState;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.config.DnsLogConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import com.reajason.javaweb.probe.config.SleepConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class ProbeGenerationServiceTest {

    private final ProbeGenerationService service = new ProbeGenerationService();

    private ProbeShellFormState baseState() {
        ProbeShellFormState s = new ProbeShellFormState();
        // Base64 根分类是聚合打包器（产出多变体），单条目断言用 DefaultBase64 变体
        s.setPackingMethod("DefaultBase64");
        return s;
    }

    @Test
    void generatesResponseBodyCommandWithBase64() {
        ProbeShellFormState s = baseState();
        DesktopProbeShellGenerateResult result = service.generate(s);

        assertNotNull(result.getProbeShellResult());
        assertNotNull(result.getProbeShellResult().getShellBytesBase64Str());
        assertFalse(result.getProbeShellResult().getShellBytesBase64Str().isEmpty());
        assertTrue(result.getProbeShellResult().getShellSize() > 0);
        assertNotNull(result.getProbeShellResult().getShellClassName());
        assertEquals("DefaultBase64", result.getPackMethod());
        assertFalse(result.isMultiResult());
        assertNotNull(result.getPackResult());
        assertFalse(result.getPackResult().isEmpty());

        ResponseConfig config = (ResponseConfig) result.getProbeShellResult().getProbeContentConfig();
        assertEquals("Tomcat", config.getServer());
        // 留空参数名 → 生成后回落到内置随机参数名
        assertNotNull(config.getReqParamName());
        assertFalse(config.getReqParamName().isEmpty());
        // ResponseBody 不使用响应头通道
        assertNull(config.getRespHeaderName());
    }

    @Test
    void explicitResponseBodyFieldsAreKept() {
        ProbeShellFormState s = baseState();
        s.setServer("Jetty");
        s.setReqParamName("input");
        s.setCommandTemplate("sh -c {command}");
        DesktopProbeShellGenerateResult result = service.generate(s);

        ResponseConfig config = (ResponseConfig) result.getProbeShellResult().getProbeContentConfig();
        assertEquals("Jetty", config.getServer());
        assertEquals("input", config.getReqParamName());
        assertEquals("sh -c {command}", config.getCommandTemplate());
    }

    @Test
    void generatesResponseHeaderProbeWithXPrefixedDefaultName() {
        ProbeShellFormState s = baseState();
        s.setProbeMethod("ResponseHeader");
        s.setProbeContent("Command");
        s.setServer("Tomcat");
        DesktopProbeShellGenerateResult result = service.generate(s);

        ResponseConfig config = (ResponseConfig) result.getProbeShellResult().getProbeContentConfig();
        assertNotNull(config.getRespHeaderName());
        assertTrue(config.getRespHeaderName().startsWith("X-"), config.getRespHeaderName());
    }

    @Test
    void explicitResponseHeaderNameIsKept() {
        ProbeShellFormState s = baseState();
        s.setProbeMethod("ResponseHeader");
        s.setProbeContent("Command");
        s.setServer("Tomcat");
        s.setRespHeaderName("X-Result");
        DesktopProbeShellGenerateResult result = service.generate(s);

        ResponseConfig config = (ResponseConfig) result.getProbeShellResult().getProbeContentConfig();
        assertEquals("X-Result", config.getRespHeaderName());
    }

    @Test
    void generatesDnsLogProbe() {
        ProbeShellFormState s = baseState();
        s.setProbeMethod("DNSLog");
        s.setProbeContent("Server");
        s.setHost("xxx.dnslog.cn");
        DesktopProbeShellGenerateResult result = service.generate(s);

        assertTrue(result.getProbeShellResult().getShellSize() > 0);
        DnsLogConfig config = (DnsLogConfig) result.getProbeShellResult().getProbeContentConfig();
        assertEquals("xxx.dnslog.cn", config.getHost());
    }

    @Test
    void generatesSleepProbe() {
        ProbeShellFormState s = baseState();
        s.setProbeMethod("Sleep");
        s.setProbeContent("Server");
        s.setSleepServer("Tomcat");
        s.setSeconds("3");
        DesktopProbeShellGenerateResult result = service.generate(s);

        assertTrue(result.getProbeShellResult().getShellSize() > 0);
        SleepConfig config = (SleepConfig) result.getProbeShellResult().getProbeContentConfig();
        assertEquals("Tomcat", config.getServer());
        assertEquals(3, config.getSeconds());
    }

    @Test
    void explicitShellClassNameIsKept() {
        ProbeShellFormState s = baseState();
        s.setShellClassName("com.example.MyProbe");
        DesktopProbeShellGenerateResult result = service.generate(s);
        assertEquals("com.example.MyProbe", result.getProbeShellResult().getShellClassName());
    }

    @Test
    void lambdaSuffixAppendsToClassName() {
        ProbeShellFormState s = baseState();
        s.setShellClassName("com.example.MyProbe");
        s.setLambdaSuffix(true);
        DesktopProbeShellGenerateResult result = service.generate(s);
        assertTrue(result.getProbeShellResult().getShellClassName().startsWith("com.example.MyProbe"));
        assertTrue(result.getProbeShellResult().getShellClassName().length() > "com.example.MyProbe".length());
    }

    @Test
    void springGzipJdk17PackerForcesExpressionPackageForProbe() {
        ProbeShellFormState s = baseState();
        s.setPackingMethod("SpELSpringGzipJDK17");
        s.setShellClassName("com.example.MyProbe");
        DesktopProbeShellGenerateResult result = service.generate(s);

        assertTrue(Packers.isSpringExpressionClassName(result.getProbeShellResult().getShellClassName()),
                result.getProbeShellResult().getShellClassName());
        assertFalse(result.getPackResult().isEmpty());
    }

    @Test
    void unknownPackerNameThrows() {
        ProbeShellFormState s = baseState();
        s.setPackingMethod("NoSuchPacker");
        try {
            service.generate(s);
            fail("should throw for unknown packer");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("NoSuchPacker"));
        }
    }
}
