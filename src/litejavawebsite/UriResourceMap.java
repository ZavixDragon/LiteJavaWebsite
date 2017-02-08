package litejavawebsite;

import java.util.Arrays;
import java.util.List;

public class UriResourceMap {
    private final List<UriResources> resources;

    public UriResourceMap(UriResources... resources) {
        this.resources = Arrays.asList(resources);
    }

    public Iterable<String> get(String uri) {
        return resources.stream().filter(x -> x.getUri().equals(uri)).findFirst().orElse(new DefaultUriResources(uri)).getResourceNames();
    }
}
