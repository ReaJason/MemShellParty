package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
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
        com.reajason.javaweb.memshell.config.GodzillaConfig config =
                (com.reajason.javaweb.memshell.config.GodzillaConfig) result.getMemShellResult().getShellToolConfig();
        assertNotNull(config.getPass());
        assertFalse(config.getPass().isEmpty());
        assertNotNull(config.getKey());
        assertFalse(config.getKey().isEmpty());
    }

    @Test
    void explicitGodzillaFieldsAreKept() {
        MemShellFormState s = baseState();
        s.setGodzillaPass("pass1234");
        s.setGodzillaKey("key12345");
        s.setHeaderName("X-Token");
        s.setHeaderValue("tok12345");
        DesktopMemShellGenerateResult result = service.generate(s);
        com.reajason.javaweb.memshell.config.GodzillaConfig config =
                (com.reajason.javaweb.memshell.config.GodzillaConfig) result.getMemShellResult().getShellToolConfig();
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
        s.setCommandParamName("cmd");
        s.setEncryptor("BASE64");
        s.setImplementationClass("ForkAndExec");
        s.setCommandTemplate("sh -c {command}");
        DesktopMemShellGenerateResult result = service.generate(s);

        com.reajason.javaweb.memshell.config.CommandConfig config =
                (com.reajason.javaweb.memshell.config.CommandConfig) result.getMemShellResult().getShellToolConfig();
        assertEquals("cmd", config.getParamName());
        assertEquals(com.reajason.javaweb.memshell.config.CommandConfig.Encryptor.BASE64, config.getEncryptor());
        assertEquals(com.reajason.javaweb.memshell.config.CommandConfig.ImplementationClass.ForkAndExec, config.getImplementationClass());
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
        s.setShellClassBase64(shellBase64);
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
        assertTrue(injectorClassName.matches("org\\.springframework\\.expression\\.[A-Z][A-Za-z]{5}Util"),
                "unexpected injector class name: " + injectorClassName);
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
        assertTrue(GenerationService.isSpringGzipJdk17RelatedPacker("SpELSpringGzipJDK17"));
        assertTrue(GenerationService.isSpringGzipJdk17RelatedPacker("OGNLSpringGzipJDK17"));
        assertTrue(GenerationService.isSpringGzipJdk17RelatedPacker("FreemarkerSpELSpringGzipJDK17"));
        assertFalse(GenerationService.isSpringGzipJdk17RelatedPacker("DefaultBase64"));
        assertFalse(GenerationService.isSpringGzipJdk17RelatedPacker(null));
    }

    @Test
    void springExpressionInjectorClassNameFormat() {
        for (int i = 0; i < 100; i++) {
            String name = GenerationService.generateSpringExpressionInjectorClassName();
            assertTrue(name.matches("org\\.springframework\\.expression\\.[A-Z][A-Za-z]{5}Util"),
                    "unexpected class name: " + name);
        }
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
