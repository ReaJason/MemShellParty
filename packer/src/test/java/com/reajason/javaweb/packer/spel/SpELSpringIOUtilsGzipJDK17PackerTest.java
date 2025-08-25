package com.reajason.javaweb.packer.spel;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packers;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2025/8/25
 */
class SpELSpringIOUtilsGzipJDK17PackerTest {

    @Test
    void pack() {
        ClassPackerConfig classPackerConfig = new ClassPackerConfig();
        classPackerConfig.setClassName("org.springframework.expression.sub.CommonUtil");
        classPackerConfig.setClassBytes("hello".getBytes());
        classPackerConfig.setClassBytesBase64Str(Base64.encodeBase64String("hello".getBytes()));
        Assertions.assertThrows(UnsupportedOperationException.class, () -> Packers.SpELSpringIOUtilsJDK17.getInstance().pack(classPackerConfig));

        classPackerConfig.setClassName("org.springframework.expression.CommonUtil");
        Assertions.assertDoesNotThrow(() -> Packers.SpELSpringIOUtilsJDK17.getInstance().pack(classPackerConfig));
    }
}