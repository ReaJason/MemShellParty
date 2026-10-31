package com.reajason.javaweb.packer;

import com.reajason.javaweb.InvalidInputException;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.probe.ProbeShellResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ServiceLoader 发现、分组目录、普通/Jar 产物与坏条目的容错。
 *
 * <p>测试资源里额外注册了一个第三方 fixture 和一条不存在的类名：坏条目不能让整个目录失败。
 *
 * @author ReaJason
 */
class PackerRegistryPackTest {

    @BeforeEach
    @AfterEach
    void resetRegistry() {
        PackerRegistry.getInstance().reset();
    }

    @Test
    void discoversBuiltInPackersAndSurvivesBrokenEntry() {
        List<String> names = PackerRegistry.getInstance().getNames();

        assertTrue(names.contains(Packers.DefaultBase64));
        assertFalse(names.contains(Packers.Base64), "Base64 只是分组名，不再有同名 packer");
        assertTrue(names.contains(Packers.JavaCommonsBeanutils17));
        assertTrue(names.contains(Packers.JavaCommonsBeanutils18));
        assertTrue(names.contains(Packers.AgentJarWithJREAttacher));
        assertTrue(names.contains(Packers.FilelessAgent));
        assertTrue(names.contains(Packers.XxlJobHessian));
        // 78 个内置注册名 + 测试 fixture
        assertEquals(79, names.size());
        assertTrue(names.contains("ThirdPartyFixture"));
        assertTrue(PackerRegistry.getInstance().getLoadErrors().stream()
                        .anyMatch(message -> message.contains("ClassDoesNotExist")),
                "缺失的 provider 类应被记录而不是中断发现");
    }

    @Test
    void buildsGroupTreeFromParentNames() {
        List<PackerCategory> tree = PackerRegistry.getInstance().getTree();
        assertEquals(34, tree.size(), "33 个内置顶层项 + 第三方 fixture");

        PackerCategory base64 = tree.stream()
                .filter(category -> Packers.Base64.equals(category.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Base64 分组应存在"));
        assertEquals(Arrays.asList(Packers.DefaultBase64, Packers.Base64URLEncoded, Packers.GzipBase64), base64.getChildren());
        assertFalse(PackerRegistry.getInstance().contains(Packers.Base64),
                "分组名不需要有同名 packer，但也不能作为打包方式");
        assertThrows(IllegalArgumentException.class, () -> PackerRegistry.getInstance().get(Packers.Base64));

        assertEquals(Arrays.asList(Packers.ClassLoaderJSP, Packers.ClassLoaderJSPUnicode, Packers.DefineClassJSP,
                        Packers.DefineClassJSPUnicode, Packers.JSPX, Packers.JSPXUnicode),
                PackerRegistry.getInstance().getChildren(Packers.JSP));
        assertEquals(Arrays.asList(Packers.JavaCommonsBeanutils19, Packers.JavaCommonsBeanutils18,
                        Packers.JavaCommonsBeanutils17, Packers.JavaCommonsBeanutils16, Packers.JavaCommonsBeanutils110,
                        Packers.JavaCommonsCollections3, Packers.JavaCommonsCollections4),
                PackerRegistry.getInstance().getChildren(Packers.JavaDeserialize));
    }

    @Test
    void packsSingleAndJarOutputs() {
        MemShellResult result = MemShellResult.builder()
                .injectorClassName("com.example.Injector")
                .injectorBytes(new byte[]{1, 2, 3})
                .injectorBytesBase64Str("injector-base64")
                .build();

        assertEquals("AQID", PackerRegistry.getInstance().pack(Packers.DefaultBase64, result));
        assertEquals("AQID", PackerRegistry.getInstance().pack(PackerRegistry.RAW, result));
    }

    @Test
    void packsStandaloneClassAndJarOutputs() throws Exception {
        ClassPackerConfig config = ClassPackerConfig.of(
                "com.example.Payload", new byte[]{1, 2, 3}, "AQID", false);

        assertEquals("AQID", PackerRegistry.getInstance().pack(Packers.DefaultBase64, config));
        assertEquals("AQID", PackerRegistry.getInstance().pack(PackerRegistry.RAW, config));

        byte[] jar = Base64.getDecoder().decode(PackerRegistry.getInstance().pack(Packers.Jar, config));
        try (JarInputStream input = new JarInputStream(new ByteArrayInputStream(jar))) {
            JarEntry entry = input.getNextJarEntry();
            assertEquals("com/example/Payload.class", entry.getName());
        }
    }

    @Test
    void rejectsStandaloneClassForFullResultOnlyPacker() {
        ClassPackerConfig config = ClassPackerConfig.of(
                "com.example.Payload", new byte[]{1, 2, 3}, "AQID", false);

        UnsupportedOperationException error = assertThrows(UnsupportedOperationException.class,
                () -> PackerRegistry.getInstance().pack(Packers.FilelessAgent, config));
        assertTrue(error.getMessage().contains("不能用于独立 class 打包"));
    }

    @Test
    void attacherPackersRejectDefaultPackageClassName() {
        JarPacker packer = config -> new byte[0];

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> packer.getPackageName("Payload"));
        assertTrue(error.getMessage().contains("命名包"));
    }

    @Test
    void probeShellsDoNotSupportJarPackers() {
        ProbeShellResult probe = ProbeShellResult.builder()
                .shellClassName("com.example.Probe")
                .shellBytesBase64Str("probe-base64")
                .build();

        assertEquals("probe-base64", PackerRegistry.getInstance().pack(PackerRegistry.RAW, probe));
        assertThrows(InvalidInputException.class,
                () -> PackerRegistry.getInstance().pack(Packers.Jar, probe));
    }

    @Test
    void thirdPartyPackerRunsWithoutAnyCodeChange() {
        ClassPackerConfig config = ClassPackerConfig.of("com.example.Injector", new byte[0], "b64", false);

        assertEquals("third-party:com.example.Injector",
                PackerRegistry.getInstance().get("ThirdPartyFixture").pack(config));
    }
}
