import com.opensymphony.xwork2.ActionSupport;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class JavaReadObjAction extends ActionSupport {

    private String data;

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
    public String execute() throws Exception {
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(decodeBase64(data));
            ObjectInputStream bis = new ObjectInputStream(inputStream);
            bis.readObject();
            bis.close();
        } catch (Exception ignored) {

        }
        return SUCCESS;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
