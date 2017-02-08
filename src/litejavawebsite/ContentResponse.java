package litejavawebsite;

public class ContentResponse {
    private final MimeType mimeType;
    private final Resource resource;

    public ContentResponse(MimeType mimeType, Resource resource) {
        this.mimeType = mimeType;
        this.resource = resource;
    }


    public NanoHTTPD.Response get() {
        return NanoHTTPD.newChunkedResponse(NanoHTTPD.Response.Status.OK, mimeType.get(), resource.get());
    }
}
