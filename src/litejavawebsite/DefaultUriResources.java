package litejavawebsite;

import java.util.Arrays;

public class DefaultUriResources implements UriResources {
    private String uri;

    public DefaultUriResources(String uri) {
        this.uri = uri;
    }

    public String getUri() {
        return uri;
    }

    public Iterable<String> getResourceNames() {
        String withoutSlash = uri.substring(1);
        return Arrays.asList(new String[] { withoutSlash + ".html", withoutSlash + ".js", withoutSlash + ".css"});
    }
}
