package litejavawebsite;

import java.io.InputStream;

public class InputStreamToString {
    private InputStream inputStream;

    public InputStreamToString(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    public String get() {
        java.util.Scanner s = new java.util.Scanner(inputStream).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }
}
