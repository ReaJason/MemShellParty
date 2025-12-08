import com.opensymphony.xwork2.ActionSupport;
import org.apache.commons.io.FileUtils;
import org.apache.struts2.ServletActionContext;

import java.io.File;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public class UploadAction extends ActionSupport {

    private File upload;
    private String uploadFileName;
    private String uploadContentType;

    private static final String UPLOAD_DIRECTORY = "/";

    @Override
    public String execute() throws Exception {
        try {
            if (upload != null) {
                String uploadFolder = ServletActionContext.getServletContext().getRealPath(UPLOAD_DIRECTORY);
                if (!uploadFolder.endsWith(File.separator)) {
                    uploadFolder += File.separator;
                }
                String uploadPath = uploadFolder + uploadFileName;
                File destFile = new File(uploadPath);
                FileUtils.copyFile(upload, destFile);
                ServletActionContext.getResponse().getWriter().println("file upload success: " + uploadPath);
            }
            return SUCCESS;
        } catch (Exception e) {
            ServletActionContext.getResponse().getWriter().println("file upload failed: " + e.getMessage());
            return ERROR;
        }
    }

    public File getUpload() {
        return upload;
    }

    public void setUpload(File upload) {
        this.upload = upload;
    }

    public String getUploadFileName() {
        return uploadFileName;
    }

    public void setUploadFileName(String uploadFileName) {
        this.uploadFileName = uploadFileName;
    }

    public String getUploadContentType() {
        return uploadContentType;
    }

    public void setUploadContentType(String uploadContentType) {
        this.uploadContentType = uploadContentType;
    }
}
