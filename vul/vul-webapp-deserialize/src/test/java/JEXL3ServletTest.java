import org.apache.commons.jexl3.*;
import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2025/1/29
 */
class JEXL3ServletTest {

    @Test
    void test() {
        System.out.println(System.getProperty("java.version"));
        JexlEngine jexl = new JexlBuilder().create();
        JexlExpression e = jexl.createExpression("''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js')");
        JexlContext jc = new MapContext();
        System.out.println(e.evaluate(jc));
    }
}