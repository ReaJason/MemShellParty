import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class FreemarkerServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String data = req.getParameter("data");
        Configuration cfg = new Configuration();
        cfg.setDefaultEncoding("UTF-8");
        Map<String, Object> input = new HashMap<String, Object>();
        input.put("object", new Object());
        Template template = new Template("templateName", new StringReader(data), cfg);
        StringWriter output = new StringWriter();
        try {
            template.process(input, output);
        } catch (TemplateException e) {
            throw new RuntimeException(e);
        }
        resp.getWriter().write(output.toString());
    }
}
