package com.reajason.javaweb.asm;

import com.reajason.javaweb.asm.fixtures.TriggerTarget;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static com.reajason.javaweb.asm.fixtures.ClassBytesTestSupport.read;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ClassNameParserTest {

    private final ClassNameParser parser = new ClassNameParser();

    @Test
    void parsesClassNameFromClassBytes() throws Exception {
        byte[] bytes = read(TriggerTarget.class);

        assertEquals(TriggerTarget.class.getName(), parser.parseClassName(bytes));
        assertEquals(TriggerTarget.class.getName(),
                parser.parseClassNameFromBase64(Base64.getEncoder().encodeToString(bytes)));
    }

    @Test
    void emptyBase64Throws() {
        assertThrows(IllegalArgumentException.class, () -> parser.parseClassNameFromBase64(null));
        assertThrows(IllegalArgumentException.class, () -> parser.parseClassNameFromBase64(""));
        assertThrows(IllegalArgumentException.class, () -> parser.parseClassNameFromBase64("   "));
    }

    @Test
    void emptyBytesThrows() {
        assertThrows(IllegalArgumentException.class, () -> parser.parseClassName(null));
        assertThrows(IllegalArgumentException.class, () -> parser.parseClassName(new byte[0]));
    }

    @Test
    void garbageBase64Throws() {
        assertThrows(Exception.class, () -> parser.parseClassNameFromBase64("!!!not-base64!!!"));
    }
}
