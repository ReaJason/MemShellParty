import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringWriter;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class VelocityServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String data = req.getParameter("data");
        StringWriter sw = new StringWriter();
        Velocity.evaluate(new VelocityContext(), sw, "tag", data);
        resp.getWriter().write(sw.toString());
    }
}
// #set($x='') $x.class.forName('javax.script.ScriptEngineManager').declaredConstructors[0].newInstance().getEngineByName('js').eval('1+1')