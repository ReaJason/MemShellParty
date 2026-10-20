package com.reajason.javaweb.memshell;

import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeShellResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 无 packer 运行时的底线行为：core 的测试类路径上没有任何 Packer provider，
 * 注册表目录为空，生成链路必须能直接输出 raw Base64。
 *
 * @author ReaJason
 */
class PackerRegistryTest {

    @BeforeEach
    @AfterEach
    void resetRegistry() {
        PackerRegistry.getInstance().reset();
    }

    @Test
    void catalogIsEmptyWithoutPackerModule() {
        assertTrue(PackerRegistry.getInstance().getTree().isEmpty());
        assertTrue(PackerRegistry.getInstance().getNames().isEmpty());
        assertFalse(PackerRegistry.getInstance().contains(Packers.Base64));
        assertFalse(PackerRegistry.getInstance().contains(""));
    }

    @Test
    void blankNamePacksMemShellInjectorAsRawBase64() {
        MemShellResult result = MemShellResult.builder()
                .injectorClassName("com.example.Injector")
                .injectorBytesBase64Str("injector-base64")
                .build();

        String output = PackerRegistry.getInstance().pack(PackerRegistry.RAW, result);

        assertEquals("injector-base64", output);
    }

    @Test
    void blankNamePacksProbeShellAsRawBase64() {
        ProbeShellResult result = ProbeShellResult.builder()
                .shellClassName("com.example.Probe")
                .shellBytesBase64Str("probe-base64")
                .build();

        String output = PackerRegistry.getInstance().pack(PackerRegistry.RAW, result);

        assertEquals("probe-base64", output);
    }

    @Test
    void unknownNameIsRejected() {
        MemShellResult result = MemShellResult.builder()
                .injectorBytesBase64Str("injector-base64")
                .build();

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> PackerRegistry.getInstance().pack(Packers.Base64, result));
        assertTrue(error.getMessage().contains(Packers.Base64));
    }
}
