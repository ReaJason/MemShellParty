import javax.script.ScriptEngineFactory;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/12/3
 */
public class ScriptEngineServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String js = req.getParameter("js");
        try {
            Object eval = new ScriptEngineManager().getEngineByName("js").eval(js);
            resp.getWriter().println(eval.toString());
        } catch (ScriptException e) {
            throw new RuntimeException(e);
        }
    }
}
