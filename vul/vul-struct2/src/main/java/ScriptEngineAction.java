import com.opensymphony.xwork2.ActionSupport;
import org.apache.struts2.ServletActionContext;

import javax.script.ScriptEngineManager;

/**
 * @author ReaJason
 * @since 2024/12/3
 */
public class ScriptEngineAction extends ActionSupport {

    private String data;

    @Override
    public String execute() throws Exception {
        try {
            Object eval = new ScriptEngineManager().getEngineByName("js").eval(data);
            ServletActionContext.getResponse().getWriter().println(eval.toString());
            return SUCCESS;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
