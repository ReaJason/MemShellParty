package jakarta;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
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
