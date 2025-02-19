package jakarta;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@WebServlet("/java_deserialize")
public class JavaReadObjServlet extends HttpServlet {
    byte[] decodeBase64(String base64Str) throws Exception {
        Class<?> decoderClass;
        try {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        } catch (Exception ignored) {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            String data = req.getParameter("data");
            ByteArrayInputStream inputStream = new ByteArrayInputStream(decodeBase64(data));
            ObjectInputStream bis = new ObjectInputStream(inputStream);
            bis.readObject();
            bis.close();
        } catch (Exception e) {
            if (e.getMessage().contains("IllegalAccessException")) {
                e.printStackTrace();
            }
        }
    }
}
