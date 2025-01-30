import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/1/30
 */
public class RhinoServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String data = req.getParameter("data");
        try (Context cx = Context.enter()) {
            Scriptable scope = cx.initStandardObjects();
            Object result = cx.evaluateString(scope, data, null, 1, null);
            resp.getWriter().print(Context.toString(result));
        }
    }
}
