import com.caucho.hessian.io.AbstractHessianInput;
import com.caucho.hessian.io.Hessian2Input;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;

/**
 * @author ReaJason
 * @since 2025/2/20
 */
@WebServlet("/hessian2")
public class Hessian2ReadObjServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String data = req.getParameter("data");
        byte[] base64 = Base64.getDecoder().decode(data);
        ByteArrayInputStream bis = new ByteArrayInputStream(base64);
        AbstractHessianInput in = new Hessian2Input(bis);
        in.readObject();
    }
}
