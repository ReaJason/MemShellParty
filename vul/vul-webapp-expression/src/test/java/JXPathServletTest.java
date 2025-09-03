import org.apache.commons.jxpath.JXPathContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author ReaJason
 * @since 2025/9/3
 */
class JXPathServletTest {

    @Test
    void test(){
        String s = "java.lang.reflect.Array.newInstance(java.lang.Class.forName('java.net.URL'), java.lang.Integer.new('1'), java.lang.Integer.new('0'))";
        JXPathContext context = JXPathContext.newContext(null);
        System.out.println(context.getValue(s));
    }

}