import javax.servlet.annotation.WebServlet;
import java.util.Collections;
import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@WebServlet("/java_deserialize/cc40")
public class JavaReadObjCC40jServlet extends BaseDeserializeServlet {

    @Override
    List<String> getDependentPaths() {
        return Collections.singletonList("commons-collections4-4.0.jar");
    }

}
