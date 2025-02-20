import javax.servlet.annotation.WebServlet;
import java.util.Arrays;
import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@WebServlet("/java_deserialize/cb183")
public class JavaReadObjCB183jServlet extends BaseDeserializeServlet {

    @Override
    List<String> getDependentPaths() {
        return Arrays.asList("commons-beanutils-1.8.3.jar", "commons-logging-1.1.1.jar");
    }

}
