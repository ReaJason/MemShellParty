import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@WebServlet("/java_deserialize/cb194")
public class JavaReadObjCB194Servlet extends BaseDeserializeServlet {

    @Override
    List<String> getDependentPaths() {
        return Arrays.asList("commons-beanutils-1.9.4.jar", "commons-logging-1.2.jar");
    }
}
