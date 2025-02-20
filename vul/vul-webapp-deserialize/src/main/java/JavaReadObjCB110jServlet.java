import javax.servlet.annotation.WebServlet;
import java.util.Arrays;
import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@WebServlet("/java_deserialize/cb110")
public class JavaReadObjCB110jServlet extends BaseDeserializeServlet {

    @Override
    List<String> getDependentPaths() {
        return Arrays.asList("commons-beanutils-1.10.0.jar", "commons-collections-3.2.2.jar", "commons-logging-1.3.4.jar");
    }

}
