import javax.servlet.*;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/1/3
 */
public class UrlMappingTestFilter implements Filter {
    @Override
    public void destroy() {

    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        chain.doFilter(request, response);
    }
}
