import com.googlecode.aviator.AviatorEvaluator;
import com.googlecode.aviator.AviatorEvaluatorInstance;
import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2025/1/29
 */
class AviatorServletTest {

    @Test
    void test() {
        String exp = "use org.springframework.cglib.core.*;use org.springframework.util.*;ReflectionUtils.invokeMethod(ClassUtils.getMethod(Class.forName('java.lang.Thread'), 'getContextClassLoader', nil), Thread.currentThread())";
        AviatorEvaluatorInstance evaluator = AviatorEvaluator.newInstance();
        System.out.println(evaluator.execute(exp));
    }
}