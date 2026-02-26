package com.reajason.javaweb.desktop.memshell.service;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class CustomClassNameParserTest {
    @Test
    void shouldParseClassNameFromClassBytesAndBase64() throws Exception {
        CustomClassNameParser parser = new CustomClassNameParser();
        byte[] bytes = readOwnClassBytes();
        String expected = this.getClass().getName();

        assertEquals(expected, parser.parseClassName(bytes));
        assertEquals(expected, parser.parseClassNameFromBase64(Base64.getEncoder().encodeToString(bytes)));
    }

    private byte[] readOwnClassBytes() throws IOException {
        String resource = "/" + this.getClass().getName().replace('.', '/') + ".class";
        InputStream in = this.getClass().getResourceAsStream(resource);
        assertNotNull(in);
        try (InputStream is = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) != -1) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }
}
