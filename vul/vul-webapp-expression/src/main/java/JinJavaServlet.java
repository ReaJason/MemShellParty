import com.google.common.collect.Maps;
import com.hubspot.jinjava.Jinjava;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/1/30
 */
@WebServlet("/jinjava")
public class JinJavaServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String data = req.getParameter("data");
        Jinjava jnj = new Jinjava();
        Map<String, Object> context = Maps.newHashMap();
        resp.getWriter().println(jnj.render(data, context));
    }
}
