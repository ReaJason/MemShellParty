import javax.servlet.annotation.WebServlet;
import java.util.Collections;
import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@WebServlet("/java_deserialize/cc321")
public class JavaReadObjCC321jServlet extends BaseDeserializeServlet {

    @Override
    List<String> getDependentPaths() {
        return Collections.singletonList("commons-collections-3.2.1.jar");
    }

}
