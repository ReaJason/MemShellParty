package jakarta;

import org.junit.jupiter.api.Test;

import javax.script.ScriptEngineManager;

/**
 * @author ReaJason
 * @since 2025/7/22
 */
class ScriptEngineServletTest {

    @Test
    void test() throws Exception {
        System.out.println(System.getProperty("java.version"));
        System.out.println(new ScriptEngineManager().getEngineByName("JavaScript").eval("var className = new java.lang.Exception().getStackTrace()[0].getClassName();" +
                        "var clazz = java.lang.Class.forName(className);" +
                        "print(clazz.getSuperclass());" +
                        "    var unsafe = null;\n" +
                        "    var rawModule = null;\n" +
                        "    var offset = 48;\n" +
                        "    var getAndSetObjectM = null;\n" +
                        "    try {\n" +
                        "        var unsafeClass = java.lang.Class.forName(\"sun.misc.Unsafe\");\n" +
                        "        var unsafeField = unsafeClass.getDeclaredField(\"theUnsafe\");\n" +
                        "        unsafeField.setAccessible(true);\n" +
                        "        unsafe = unsafeField.get(null);\n" +
                        "        rawModule = java.lang.Class.class.getMethod(\"getModule\").invoke(clazz.getSuperclass(), []);\n" +
                        "print(rawModule);" +
                        "        var module = java.lang.Class.class.getMethod(\"getModule\").invoke(java.lang.Object.class, []);\n" +
                        "print(module);" +
                        "        var objectFieldOffsetM = unsafe.getClass().getMethod(\"objectFieldOffset\", java.lang.reflect.Field.class);\n" +
                        "        offset = objectFieldOffsetM.invoke(unsafe, java.lang.Class.class.getDeclaredField(\"module\"));\n" +
                        "        getAndSetObjectM = unsafe.getClass().getMethod(\"getAndSetObject\", java.lang.Object.class, java.lang.Long.TYPE, java.lang.Object.class);\n" +
                        "        getAndSetObjectM.invoke(unsafe, clazz.getSuperclass(), offset, module);\n" +
                        "print(new java.lang.Exception().getStackTrace()[0].getClassName());print(new java.lang.Exception().getStackTrace()[0].getClassName());print(new java.lang.Exception().getStackTrace()[0].getClassName());" +
                        "print(java.lang.Class.class.getMethod(\"getModule\").invoke(clazz.getSuperclass(), []));" +
                        "    } catch (ignored) {\n" +
                        "ignored.printStackTrace();\n" +
                        "    }" +
                        "var clsByteArray = (new java.lang.String(\"a\").getBytes().getClass());" +
                        "var clsString = java.lang.Class.forName(\"java.lang.String\");" +
                        "var clsInt = java.lang.Integer.TYPE;" +
                        "print(new java.lang.Exception().getStackTrace()[0].getClassName());" +
                        "print(new java.lang.Exception().getStackTrace()[0].getClassName());" +
                        "print(new java.lang.Exception().getStackTrace()[0].getClassName());" +
                        "var defineClass = java.lang.Class.forName(\"java.lang.ClassLoader\").getDeclaredMethod(\"defineClass\", [clsString, clsByteArray, clsInt, clsInt]);" +
                        "defineClass.setAccessible(true);"
                )
        );
    }
}