package com.reajason.javaweb.packer.aviator;

import com.reajason.javaweb.packer.ClassPackerConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Aviator 会把表达式编译成 bytecode，单个字符串字面量超过 65535 会导致 define class 失败；
 * 超长 base64 必须拆成多个字面量运行期相加。
 */
class AviatorPackerTest {

    @Test
    void longPayloadIsConcatenated() {
        ClassPackerConfig config = new ClassPackerConfig();
        config.setClassName("com.example.Test");
        char[] chars = new char[70_000];
        java.util.Arrays.fill(chars, 'A');
        String base64 = new String(chars);
        config.setClassBytesBase64Str(base64);

        String payload = new AviatorPacker().pack(config);
        assertTrue(payload.contains("' + '"), "long payload should be concatenated at runtime");
        assertFalse(payload.contains(base64), "payload should not keep one oversized literal");
    }
}
