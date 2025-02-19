import ognl.Ognl;
import ognl.OgnlContext;
import ognl.OgnlException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
@WebServlet("/ognl")
public class OgnlServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String data = req.getParameter("data");
        OgnlContext context = new OgnlContext();
        Object value = null;
        try {
            value = Ognl.getValue(data, context, context.getRoot());
        } catch (OgnlException e) {
            throw new RuntimeException(e);
        }
        resp.getWriter().println(value);
    }
}
