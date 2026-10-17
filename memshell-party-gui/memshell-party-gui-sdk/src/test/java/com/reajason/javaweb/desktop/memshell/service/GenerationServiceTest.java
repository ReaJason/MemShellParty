package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GenerationServiceTest {

    private final GenerationService service = new GenerationService();

    @Test
    void generatesGodzillaListenerWithDefaultBase64() {
        MemShellFormState s = baseState();
        DesktopMemShellGenerateResult result = service.generate(s);

        assertNotNull(result.getMemShellResult());
        assertNotNull(result.getMemShellResult().getShellBytesBase64Str());
        assertFalse(result.getMemShellResult().getShellBytesBase64Str().isEmpty());
        assertNotNull(result.getMemShellResult().getInjectorBytesBase64Str());
        assertTrue(result.getMemShellResult().getShellSize() > 0);
        assertTrue(result.getMemShellResult().getInjectorSize() > 0);
        assertEquals("DefaultBase64", result.getPackMethod());
        assertFalse(result.isMultiResult());
        assertNotNull(result.getPackResult());
        assertFalse(result.getPackResult().isEmpty());
    }

    @Test
    void jarPackerProducesZipMagic() {
        MemShellFormState s = baseState();
        s.setPackingMethod("Jar");
        DesktopMemShellGenerateResult result = service.generate(s);

        assertTrue(result.isJarOutput());
        byte[] bytes = Base64.getDecoder().decode(result.getPackResult());
        assertEquals(0x50, bytes[0] & 0xFF); // 'P'
        assertEquals(0x4B, bytes[1] & 0xFF); // 'K'
    }

    @Test
    void blankFieldsFallBackToRandom() {
        MemShellFormState s = baseState();
        // 留空 pass/key → 生成后从结果 config 读随机值
        DesktopMemShellGenerateResult result = service.generate(s);
        com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig config =
                (com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig) result.getMemShellResult().getShellToolConfig();
        assertNotNull(config.getPass());
        assertFalse(config.getPass().isEmpty());
        assertNotNull(config.getKey());
        assertFalse(config.getKey().isEmpty());
    }

    @Test
    void explicitGodzillaFieldsAreKept() {
        MemShellFormState s = baseState();
        s.setToolParam("pass", "pass1234");
        s.setToolParam("key", "key12345");
        s.setToolParam("headerName", "X-Token");
        s.setToolParam("headerValue", "tok12345");
        DesktopMemShellGenerateResult result = service.generate(s);
        com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig config =
                (com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig) result.getMemShellResult().getShellToolConfig();
        assertEquals("pass1234", config.getPass());
        assertEquals("key12345", config.getKey());
        assertEquals("X-Token", config.getHeaderName());
        assertEquals("tok12345", config.getHeaderValue());
    }

    @Test
    void commandWithExplicitAdvancedConfig() {
        MemShellFormState s = baseState();
        s.setShellTool("Command");
        s.setShellType("Servlet");
        s.setUrlPattern("/cmd");
        s.setToolParam("paramName", "cmd");
        s.setToolParam("encryptor", "BASE64");
        s.setToolParam("implementationClass", "ForkAndExec");
        s.setToolParam("template", "sh -c {command}");
        DesktopMemShellGenerateResult result = service.generate(s);

        com.reajason.javaweb.memshell.shelltool.command.CommandConfig config =
                (com.reajason.javaweb.memshell.shelltool.command.CommandConfig) result.getMemShellResult().getShellToolConfig();
        assertEquals("cmd", config.getParamName());
        assertEquals(com.reajason.javaweb.memshell.shelltool.command.CommandConfig.Encryptor.BASE64, config.getEncryptor());
        assertEquals(com.reajason.javaweb.memshell.shelltool.command.CommandConfig.ImplementationClass.ForkAndExec, config.getImplementationClass());
        // urlPattern 取生成后的 injectorConfig
        assertEquals("/cmd", result.getMemShellResult().getInjectorConfig().getUrlPattern());
    }

    @Test
    void customFlowWithGeneratedShell() {
        // 先生成一个 Godzilla shell，再把它作为 Custom 的 shellClassBase64；
        // 类名来自字节码本身，两次生成的随机类名一致
        MemShellFormState first = baseState();
        DesktopMemShellGenerateResult firstResult = service.generate(first);
        String shellBase64 = firstResult.getMemShellResult().getShellBytesBase64Str();

        MemShellFormState s = baseState();
        s.setShellTool("Custom");
        s.setToolParam(MemShellFormState.PARAM_SHELL_CLASS_BASE64, shellBase64);
        DesktopMemShellGenerateResult result = service.generate(s);

        assertNotNull(result.getMemShellResult());
        assertEquals(firstResult.getMemShellResult().getShellClassName(), result.getMemShellResult().getShellClassName());
        assertFalse(result.getPackResult().isEmpty());
    }

    @Test
    void aggregatePackerProducesMultiResults() {
        MemShellFormState s = baseState();
        s.setPackingMethod("JavaDeserialize");
        DesktopMemShellGenerateResult result = service.generate(s);

        assertTrue(result.isMultiResult());
        Map<String, String> entries = result.getPackResults();
        assertNotNull(entries);
        assertFalse(entries.isEmpty());
        assertNotNull(result.getActivePackResult());
    }

    @Test
    void unknownPackerNameThrows() {
        MemShellFormState s = baseState();
        s.setPackingMethod("NoSuchPacker");
        try {
            service.generate(s);
            org.junit.jupiter.api.Assertions.fail("should throw for unknown packer");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("NoSuchPacker"));
        }
    }

    @Test
    void springGzipJdk17PackerOverridesInjectorClassName() {
        MemShellFormState s = baseState();
        s.setPackingMethod("SpELSpringGzipJDK17");
        s.setInjectorClassName("com.example.UserInjector");
        DesktopMemShellGenerateResult result = service.generate(s);

        String injectorClassName = result.getMemShellResult().getInjectorConfig().getInjectorClassName();
        assertNotNull(injectorClassName);
        assertTrue(injectorClassName.matches("org\\.springframework\\.expression\\.[A-Z][A-Za-z0-9]*Utils"),
                "unexpected injector class name: " + injectorClassName);
        assertFalse(result.getPackResult().isEmpty());
    }

    @Test
    void springGzipJdk17PackerKeepsValidExpressionClassName() {
        MemShellFormState s = baseState();
        s.setPackingMethod("SpELSpringGzipJDK17");
        s.setInjectorClassName("org.springframework.expression.UserInjector");
        DesktopMemShellGenerateResult result = service.generate(s);

        assertEquals("org.springframework.expression.UserInjector",
                result.getMemShellResult().getInjectorConfig().getInjectorClassName());
        assertFalse(result.getPackResult().isEmpty());
    }

    @Test
    void nonSpringGzipJdk17PackerKeepsUserInjectorClassName() {
        MemShellFormState s = baseState();
        s.setInjectorClassName("com.example.UserInjector");
        DesktopMemShellGenerateResult result = service.generate(s);

        assertEquals("com.example.UserInjector",
                result.getMemShellResult().getInjectorConfig().getInjectorClassName());
    }

    @Test
    void springGzipJdk17PackerDetection() {
        assertTrue(Packers.SpELSpringGzipJDK17.requiresSpringExpressionPackage());
        assertTrue(Packers.OGNLSpringGzipJDK17.requiresSpringExpressionPackage());
        assertTrue(Packers.FreemarkerSpELSpringGzipJDK17.requiresSpringExpressionPackage());
        assertFalse(Packers.DefaultBase64.requiresSpringExpressionPackage());
        assertTrue(Packers.isSpringExpressionClassName("org.springframework.expression.SessionUtils"));
        assertFalse(Packers.isSpringExpressionClassName("org.springframework.expression.sub.SessionUtils"));
    }

    @Test
    void springExpressionInjectorClassNameFormat() {
        for (int i = 0; i < 100; i++) {
            String name = Packers.SpELSpringGzipJDK17.generateSpringExpressionClassName();
            assertTrue(name.matches("org\\.springframework\\.expression\\.[A-Z][A-Za-z0-9]*Utils"),
                    "unexpected class name: " + name);
        }
    }

    @Test
    void generateShellReturnsRawResultWithoutPacking() {
        // 不打包路线（Shiro 反序列化注入这类宿主）：injector 字节直接可用，用户填的注入器类名保留
        MemShellFormState s = baseState();
        s.setInjectorClassName("com.example.UserInjector");
        s.setPackingMethod("NoSuchPacker");   // generateShell 不碰 packer，非法打包名不应影响
        com.reajason.javaweb.memshell.MemShellResult result = service.generateShell(s);

        assertNotNull(result.getShellBytesBase64Str());
        assertNotNull(result.getInjectorBytes());
        assertTrue(result.getInjectorBytes().length > 0);
        assertEquals("com.example.UserInjector", result.getInjectorConfig().getInjectorClassName());
    }

    private MemShellFormState baseState() {
        MemShellFormState s = new MemShellFormState();
        s.setServer("Tomcat");
        s.setServerVersion("Unknown");
        s.setShellTool("Godzilla");
        s.setShellType("Listener");
        s.setPackingMethod("DefaultBase64");
        return s;
    }
}
