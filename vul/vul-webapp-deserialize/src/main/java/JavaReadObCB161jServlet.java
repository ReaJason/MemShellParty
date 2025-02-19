import javax.servlet.annotation.WebServlet;
import java.util.Arrays;
import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@WebServlet("/java_deserialize/cb161")
public class JavaReadObCB161jServlet extends BaseDeserializeServlet {

    @Override
    List<String> getDependentPaths() {
        return Arrays.asList("commons-beanutils-1.6.1.jar", "commons-collections-2.0.jar", "commons-logging-1.0.jar");
    }

}
