package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Collections;

class JspCustomPackerConfigTest {

    @Test
    void classLoaderJspShouldApplyUnicodeWhenEnabled() {
        ClassLoaderJspPacker packer = new ClassLoaderJspPacker();
        ClassPackerConfig<JspCustomPackerConfig> config = buildConfig();
        config.setCustomConfig(packer.resolveCustomConfig(null));

        String plain = packer.pack(config);
        config.setCustomConfig(packer.resolveCustomConfig(Collections.singletonMap("unicode", true)));
        String unicode = packer.pack(config);

        Assertions.assertEquals(JspUnicoder.encode(plain, true), unicode);
    }

    @Test
    void defineClassJspShouldApplyUnicodeWhenEnabled() {
        DefineClassJspPacker packer = new DefineClassJspPacker();
        ClassPackerConfig<JspCustomPackerConfig> config = buildConfig();
        config.setCustomConfig(packer.resolveCustomConfig(null));

        String plain = packer.pack(config);
        config.setCustomConfig(packer.resolveCustomConfig(Collections.singletonMap("unicode", true)));
        String unicode = packer.pack(config);

        Assertions.assertEquals(JspUnicoder.encode(plain, true), unicode);
    }

    @Test
    void jspxShouldApplyUnicodeWhenEnabled() {
        JspxPacker packer = new JspxPacker();
        ClassPackerConfig<JspCustomPackerConfig> config = buildConfig();
        config.setCustomConfig(packer.resolveCustomConfig(null));

        String plain = packer.pack(config);
        config.setCustomConfig(packer.resolveCustomConfig(Collections.singletonMap("unicode", true)));
        String unicode = packer.pack(config);

        Assertions.assertEquals(JspUnicoder.encode(plain, false), unicode);
    }

    @Test
    void defaultShouldDisableUnicode() {
        ClassLoaderJspPacker packer = new ClassLoaderJspPacker();
        ClassPackerConfig<JspCustomPackerConfig> config = buildConfig();
        config.setCustomConfig(packer.resolveCustomConfig(null));
        String plain = packer.pack(config);

        config.setCustomConfig(packer.resolveCustomConfig(Collections.emptyMap()));
        Assertions.assertEquals(plain, packer.pack(config));
    }

    @Test
    void invalidUnicodeTypeShouldThrow() {
        ClassLoaderJspPacker packer = new ClassLoaderJspPacker();
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> packer.resolveCustomConfig(Collections.singletonMap("unicode", "oops")));
    }

    private static ClassPackerConfig<JspCustomPackerConfig> buildConfig() {
        ClassPackerConfig<JspCustomPackerConfig> config = new ClassPackerConfig<>();
        config.setClassName("hello.world.Injector");
        config.setClassBytesBase64Str("QUJDRA==");
        config.setClassBytes(new byte[]{1, 2, 3, 4});
        return config;
    }
}
