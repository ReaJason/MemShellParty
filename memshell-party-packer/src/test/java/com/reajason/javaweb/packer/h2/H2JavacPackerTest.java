package com.reajason.javaweb.packer.h2;

import com.reajason.javaweb.packer.ClassPackerConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.ToolProvider;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * H2 的 {@code CREATE ALIAS ... AS 'java source'} 由运行期 javac 编译，超长 base64
 * 字面量同样会撞上 class 常量池 65535 上限。
 */
class H2JavacPackerTest {

    @Test
    void longPayloadCompiles(@TempDir Path tempDir) throws Exception {
        for (boolean byPassJavaModule : new boolean[]{false, true}) {
            ClassPackerConfig config = new ClassPackerConfig();
            config.setByPassJavaModule(byPassJavaModule);
            char[] chars = new char[70_000];
            java.util.Arrays.fill(chars, 'A');
            config.setClassBytesBase64Str(new String(chars));

            String url = new H2JavacPacker().pack(config);
            assertTrue(url.contains(".concat("),
                    "long payload should be concatenated at runtime");
            compileAliasSource(url, tempDir, "H2Alias" + byPassJavaModule);
        }
    }

    /**
     * 让 H2 自己编译别名源码（去掉 CALL look('')，只编译不执行 defineClass）。
     */
    @Test
    void longPayloadCompilesInH2() throws Exception {
        ClassPackerConfig config = new ClassPackerConfig();
        char[] chars = new char[70_000];
        java.util.Arrays.fill(chars, 'A');
        config.setClassBytesBase64Str(new String(chars));

        String url = new H2JavacPacker().pack(config);
        int call = url.indexOf("\\;CALL look('')");
        assertTrue(call > 0, "CALL statement not found");
        String initUrl = url.substring(0, call).replace(";TRACE_LEVEL_SYSTEM_OUT=3", "");
        try (java.sql.Connection ignored = java.sql.DriverManager.getConnection(initUrl)) {
            // H2 executes INIT / CREATE ALIAS and compiles the alias source on connect.
        }
    }

    private static void compileAliasSource(String url, Path tempDir, String className) throws Exception {
        String marker = "CREATE ALIAS look AS '";
        int start = url.indexOf(marker);
        assertTrue(start >= 0, "alias source not found");
        start += marker.length();
        int end = url.indexOf("'\\;", start);
        assertTrue(end > start, "alias source end not found");
        String methodSource = url.substring(start, end).replace("\\;", ";");

        Path sourceDir = Files.createDirectories(tempDir.resolve("src-" + className));
        Path classesDir = Files.createDirectories(tempDir.resolve("classes-" + className));
        Path sourceFile = sourceDir.resolve(className + ".java");
        String source = "public class " + className + " {\n"
                + "    public static " + methodSource + "\n"
                + "}\n";
        Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));

        int exitCode = ToolProvider.getSystemJavaCompiler().run(null, null, null,
                "-d", classesDir.toString(), sourceFile.toString());
        assertEquals(0, exitCode, "H2 alias source should compile");
    }
}
