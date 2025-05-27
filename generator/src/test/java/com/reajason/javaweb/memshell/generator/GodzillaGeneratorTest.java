package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import com.reajason.javaweb.util.ClassDefiner;
import com.reajason.javaweb.util.ClassUtils;
import lombok.SneakyThrows;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;

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
                .shellType(ShellType.SERVLET)
                .targetJreVersion(Opcodes.V1_6)
                .debug(true)
                .build();
        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .shellClass(GodzillaServlet.class)
                .shellClassName(CommonUtil.generateShellClassName())
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("test").build();
        byte[] bytes = new GodzillaGenerator(shellConfig, godzillaConfig).getBytes();
        Class<?> loaded = ClassDefiner.defineClass(bytes);
        Object o = loaded.getDeclaredConstructor().newInstance();
        assertEquals(godzillaConfig.getPass(), ClassUtils.getFieldValue(o, "pass"));
        assertEquals(godzillaConfig.getHeaderName(), ClassUtils.getFieldValue(o, "headerName"));
        assertEquals(godzillaConfig.getHeaderValue(), ClassUtils.getFieldValue(o, "headerValue"));
    }
}