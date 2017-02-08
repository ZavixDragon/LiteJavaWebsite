package litejavawebsite;

import java.util.HashMap;
import java.util.Map;

public class MimeType {
    public final Map<String, String> mimeTypes = new HashMap<String, String>() {{
        put("html", "text/html");
        put("js", "text/javascript");
        put("css", "text/css");
        put("ico", "image/x-icon");
    }};
    private final FileExtension extension;

    public MimeType(FileExtension extension) {
        this.extension = extension;
    }

    public String get() {
        return mimeTypes.get(extension.get());
    }
}
