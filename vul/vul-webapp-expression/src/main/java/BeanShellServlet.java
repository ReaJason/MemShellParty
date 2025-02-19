import bsh.EvalError;
import bsh.Interpreter;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/1/30
 */
@WebServlet("/bsh")
public class BeanShellServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String data = req.getParameter("data");
        Interpreter i = new Interpreter();
        try {
            Object eval = i.eval(data);
            resp.getWriter().println(eval);
        } catch (EvalError e) {
            throw new RuntimeException(e);
        }
    }
}
