package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.util.ClassUtils;
import lombok.SneakyThrows;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2025/1/1
 */
class GodzillaGeneratorTest {

    @Test
    @SneakyThrows
    void generate() {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(ShellTool.Godzilla)
                .shellType(Constants.SERVLET)
                .targetJreVersion(Opcodes.V1_6)
                .debug(true)
                .build();
        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .shellClass(GodzillaServlet.class)
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("test").build();
        DynamicType.Builder<?> builder = new GodzillaGenerator(shellConfig, godzillaConfig).getBuilder();
        Class<?> loaded = builder.make().load(this.getClass().getClassLoader()).getLoaded();
        Object o = loaded.getDeclaredConstructor().newInstance();
        assertEquals(godzillaConfig.getPass(), ClassUtils.getFieldValue(o, "pass"));
        assertEquals(godzillaConfig.getHeaderName(), ClassUtils.getFieldValue(o, "headerName"));
        assertEquals(godzillaConfig.getHeaderValue(), ClassUtils.getFieldValue(o, "headerValue"));
    }
}