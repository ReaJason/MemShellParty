import org.apache.commons.jexl2.Expression;
import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2025/1/29
 */
class JEXL2ServletTest {

    @Test
    void test() {
        System.out.println(System.getProperty("java.version"));
        org.apache.commons.jexl2.JexlEngine jexl = new org.apache.commons.jexl2.JexlEngine();
        Expression e = jexl.createExpression("''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js')");
        org.apache.commons.jexl2.MapContext jc = new org.apache.commons.jexl2.MapContext();
        System.out.println(e.evaluate(jc));
    }
}