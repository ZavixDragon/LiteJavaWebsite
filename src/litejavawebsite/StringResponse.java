package litejavawebsite;

public class StringResponse {
    private final MimeType mimeType;
    private final String content;

    public StringResponse(MimeType mimeType, String content) {
        this.mimeType = mimeType;
        this.content = content;
    }

    public NanoHTTPD.Response get() {
        return NanoHTTPD.newFixedLengthResponse(NanoHTTPD.Response.Status.OK, mimeType.get(), content);
    }
}
