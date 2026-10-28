package com.reajason.javaweb.bytecode;

import com.reajason.javaweb.bytecode.fixtures.TriggerTarget;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CustomClassNameParserTest {

    private final CustomClassNameParser parser = new CustomClassNameParser();

    @Test
    void parsesClassNameFromClassBytes() throws Exception {
        byte[] bytes;
        InputStream in = TriggerTarget.class.getResourceAsStream(TriggerTarget.class.getSimpleName() + ".class");
        assertNotNull(in);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            bytes = out.toByteArray();
        } finally {
            in.close();
        }

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
