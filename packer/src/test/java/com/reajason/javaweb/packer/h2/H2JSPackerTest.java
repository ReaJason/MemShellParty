package com.reajason.javaweb.packer.h2;

import com.reajason.javaweb.packer.ClassPackerConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author ReaJason
 * @since 2025/6/28
 */
class H2JSPackerTest {

    @Test
    void test() {
        H2JSPacker h2JSPacker = new H2JSPacker();
        ClassPackerConfig classPackerConfig = new ClassPackerConfig();
        classPackerConfig.setClassBytesBase64Str("bebe");
        System.out.println(h2JSPacker.pack(classPackerConfig));
    }
}