import org.apache.commons.jxpath.JXPathContext;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class JXPathServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String data = req.getParameter("data");
        JXPathContext context = JXPathContext.newContext(null);
        resp.getWriter().println(context.getValue(data));
    }
}
