import ognl.Ognl;
import ognl.OgnlContext;
import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2025/7/22
 */
class OgnlServletTest {

    @Test
    void test() throws Exception {
        OgnlContext context = new OgnlContext();
        Object value = null;
        System.out.println(Ognl.getValue("(new java.io.File('.')).list()", context, context.getRoot()));
    }
}