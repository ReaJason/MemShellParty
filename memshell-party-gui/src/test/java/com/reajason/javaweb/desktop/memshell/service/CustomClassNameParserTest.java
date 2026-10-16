package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CustomClassNameParserTest {

    private final CustomClassNameParser parser = new CustomClassNameParser();
    private final GenerationService generationService = new GenerationService();

    @Test
    void parsesClassNameFromGeneratedShell() {
        MemShellFormState s = baseState();
        com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult result = generationService.generate(s);
        String shellClassName = result.getMemShellResult().getShellClassName();
        String shellBase64 = result.getMemShellResult().getShellBytesBase64Str();

        String parsed = parser.parseClassNameFromBase64(shellBase64);
        assertEquals(shellClassName, parsed);

        byte[] bytes = Base64.getDecoder().decode(shellBase64);
        assertEquals(shellClassName, parser.parseClassName(bytes));
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

    private MemShellFormState baseState() {
        MemShellFormState s = new MemShellFormState();
        s.setServer("Tomcat");
        s.setServerVersion("Unknown");
        s.setShellTool("Godzilla");
        s.setShellType("Listener");
        s.setPackingMethod("DefaultBase64");
        return s;
    }
}
