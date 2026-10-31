package com.reajason.javaweb.examples.customgui.packer;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.examples.customgui.server.DemoServerProvider;
import com.reajason.javaweb.examples.customgui.shelltool.GodzillaSessionShellToolProvider;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 自定义 packer 的生成期验证：SPI 发现、分组展示、URL-safe 输出，
 * 以及 GUI 生成链路能选到它并把注入器字节完整还原。
 *
 * @author ReaJason
 */
class CustomPackerTest {

    @Test
    void spiDiscoversTheCustomPacker() {
        PackerRegistry registry = PackerRegistry.getInstance();
        assertTrue(registry.getNames().contains(GzipBase64URLPacker.NAME),
                GzipBase64URLPacker.NAME + " not registered: " + registry.getNames());
        // 元数据同样来自 SPI：分组
        Packer packer = registry.get(GzipBase64URLPacker.NAME);
        PackerMeta meta = packer.getClass().getAnnotation(PackerMeta.class);
        assertEquals(Packers.Base64, meta.parent());
    }

    @Test
    void customPackerIsListedUnderTheBase64Group() {
        List<String> children = PackerRegistry.getInstance().getChildren(Packers.Base64);
        assertTrue(children.contains(GzipBase64URLPacker.NAME), children.toString());
        // 内置 Base64 packer 不受影响：插件是加进去的，不是替换
        assertTrue(children.contains(Packers.DefaultBase64), children.toString());
    }

    @Test
    void packsUrlSafeGzipBase64() throws Exception {
        byte[] bytes = "custom packer payload".getBytes(StandardCharsets.UTF_8);
        String packed = PackerRegistry.getInstance().get(GzipBase64URLPacker.NAME)
                .pack(ClassPackerConfig.of("com.example.Shell", bytes, Base64.getEncoder().encodeToString(bytes), false));

        assertFalse(packed.contains("+"), "URL-safe Base64 不应出现 +");
        assertFalse(packed.contains("/"), "URL-safe Base64 不应出现 /");
        assertFalse(packed.contains("="), "URL-safe Base64 不应带 padding");
        assertArrayEquals(bytes, gunzip(Base64.getUrlDecoder().decode(packed)));
    }

    @Test
    void guiGenerationCanUseTheCustomPacker() throws Exception {
        MemShellFormState state = new MemShellFormState();
        // 三块自定义 SPI 一起走：自定义 server + 自定义 shelltool + 自定义 packer
        state.setServer(DemoServerProvider.NAME);
        state.setServerVersion("Unknown");
        state.setShellTool(GodzillaSessionShellToolProvider.NAME);
        state.setShellType(ShellType.FILTER);
        state.setPackingMethod(GzipBase64URLPacker.NAME);

        DesktopMemShellGenerateResult result = new GenerationService().generate(state);

        assertEquals(GzipBase64URLPacker.NAME, result.getPackMethod());
        assertFalse(result.isJarOutput());
        assertArrayEquals(result.getMemShellResult().getInjectorBytes(),
                gunzip(Base64.getUrlDecoder().decode(result.getPackResult())));
    }

    private static byte[] gunzip(byte[] data) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(data))) {
            byte[] buffer = new byte[4096];
            int n;
            while ((n = in.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
        }
        return out.toByteArray();
    }
}
