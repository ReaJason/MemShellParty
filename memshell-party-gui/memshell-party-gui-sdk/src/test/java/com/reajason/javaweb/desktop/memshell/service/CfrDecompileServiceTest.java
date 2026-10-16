package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CfrDecompileServiceTest {

    private final CfrDecompileService decompileService = new CfrDecompileService();
    private final GenerationService generationService = new GenerationService();

    @Test
    void decompilesGeneratedShellClass() {
        DesktopMemShellGenerateResult result = generationService.generate(baseState());
        String className = result.getMemShellResult().getShellClassName();
        byte[] bytes = Base64.getDecoder().decode(result.getMemShellResult().getShellBytesBase64Str());

        String source = decompileService.decompile(className, bytes);

        assertFalse(source.isEmpty());
        // 简单类名应出现在反编译源码中（含 Godzilla Listener 挂载痕迹）
        String simpleName = className.substring(className.lastIndexOf('.') + 1);
        assertTrue(source.contains(simpleName), "source should contain class name:\n" + source);
    }

    @Test
    void decompilesGeneratedInjectorClass() {
        DesktopMemShellGenerateResult result = generationService.generate(baseState());
        String className = result.getMemShellResult().getInjectorClassName();
        byte[] bytes = Base64.getDecoder().decode(result.getMemShellResult().getInjectorBytesBase64Str());

        String source = decompileService.decompile(className, bytes);

        assertFalse(source.isEmpty());
        String simpleName = className.substring(className.lastIndexOf('.') + 1);
        assertTrue(source.contains(simpleName), "source should contain class name:\n" + source);
    }

    @Test
    void rejectsBlankClassName() {
        assertThrows(IllegalArgumentException.class,
                () -> decompileService.decompile(" ", new byte[]{1, 2, 3}));
    }

    @Test
    void rejectsEmptyBytes() {
        assertThrows(IllegalArgumentException.class,
                () -> decompileService.decompile("com.example.Foo", new byte[0]));
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
