package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.ToolProvider;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
class JspPackerTest {

    @Test
    void pack() {
        MemShellResult generateResult = MemShellResult.builder()
                .injectorClassName("hehe")
                .injectorBytesBase64Str("hehe").build();
        String jspContent = new JspPacker().pack(ClassPackerConfig.from(generateResult));
        assertTrue(jspContent.contains("String base64Str = \"hehe\";"));
    }

    /**
     * Resin 等容器用自带的旧版 javac 编译 JSP：单个字符串常量的 modified UTF-8 长度超过
     * 65535 时会直接抛 UTFDataFormatException。混淆后的 NeoreGeorg injector base64 约 68KB，
     * 打包器必须拆成多个字面量并在运行期拼接（编译期折叠仍会合并回一个超长常量）。
     * <p>
     * 拼接只能用 {@link String#concat(String)}：WebLogic 10.3.6 的 JSP 编译器（repackaged
     * ECJ 3.5.3）解析不了 {@code java.lang.CharSequence}，{@code new StringBuilder()
     * .append(...)} 会直接编译失败。
     */
    @Test
    void longPayloadIsChunkedAndStillCompiles(@TempDir Path tempDir) throws Exception {
        String base64 = repeat('A', 70_000);
        ClassPackerConfig config = ClassPackerConfig.of("hehe", new byte[0], base64, false);

        Packers[] packers = {
                Packers.ClassLoaderJSP,
                Packers.DefineClassJSP,
                Packers.JSPX,
                Packers.ClassLoaderJSPUnicode,
                Packers.DefineClassJSPUnicode,
                Packers.JSPXUnicode
        };
        int index = 0;
        for (Packers packer : packers) {
            String content = packer.getInstance().pack(config);
            boolean unicode = packer.name().endsWith("Unicode");
            String decoded = unicode ? decodeUnicodeEscapes(content) : content;

            assertTrue(decoded.contains(".concat("),
                    packer.name() + " should concatenate long payload at runtime");
            assertFalse(decoded.contains("StringBuilder"),
                    packer.name() + " must not reference CharSequence-dependent APIs");
            assertFalse(decoded.contains(base64),
                    packer.name() + " should not emit one oversized string literal");

            String expression = extractBase64Expression(decoded);
            assertEquals(base64, compileAndEvaluate(expression, tempDir, "T" + index++));
        }
    }

    private static String extractBase64Expression(String content) {
        String marker = "String base64Str = ";
        int start = content.indexOf(marker);
        assertTrue(start >= 0, "base64Str assignment not found");
        start += marker.length();
        int end = content.indexOf(';', start);
        assertTrue(end > start, "base64Str assignment end not found");
        return content.substring(start, end);
    }

    private static String compileAndEvaluate(String expression, Path tempDir, String className) throws Exception {
        Path sourceDir = Files.createDirectories(tempDir.resolve("src-" + className));
        Path classesDir = Files.createDirectories(tempDir.resolve("classes-" + className));
        Path sourceFile = sourceDir.resolve(className + ".java");
        String source = "public class " + className + " {\n"
                + "    public static String value = " + expression + ";\n"
                + "}\n";
        Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));

        int exitCode = ToolProvider.getSystemJavaCompiler().run(null, null, null,
                "-d", classesDir.toString(), sourceFile.toString());
        assertEquals(0, exitCode, "generated Java source should compile");

        try (URLClassLoader loader = new URLClassLoader(new URL[]{classesDir.toUri().toURL()},
                JspPackerTest.class.getClassLoader())) {
            Class<?> clazz = loader.loadClass(className);
            return (String) clazz.getField("value").get(null);
        }
    }

    private static String decodeUnicodeEscapes(String content) {
        StringBuilder decoded = new StringBuilder(content.length());
        for (int i = 0; i < content.length(); i++) {
            char ch = content.charAt(i);
            if (ch == '\\' && i + 5 < content.length() && content.charAt(i + 1) == 'u') {
                decoded.append((char) Integer.parseInt(content.substring(i + 2, i + 6), 16));
                i += 5;
            } else {
                decoded.append(ch);
            }
        }
        return decoded.toString();
    }

    private static String repeat(char ch, int count) {
        char[] chars = new char[count];
        java.util.Arrays.fill(chars, ch);
        return new String(chars);
    }
}
