import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/12/3
 */
public class ScriptEngineServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String data = req.getParameter("data");
        try {
            Object eval = new ScriptEngineManager().getEngineByName("js").eval(data);
            resp.getWriter().println(eval.toString());
        } catch (ScriptException e) {
            throw new RuntimeException(e);
        }
    }
}
