import javax.servlet.annotation.WebServlet;
import java.util.Arrays;
import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@WebServlet("/java_deserialize/cb170")
public class JavaReadObCB170jServlet extends BaseDeserializeServlet {

    @Override
    List<String> getDependentPaths() {
        return Arrays.asList("commons-beanutils-1.7.0.jar", "commons-logging-1.0.3.jar");
    }

}
