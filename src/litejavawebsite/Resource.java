package litejavawebsite;

import java.io.InputStream;
import java.util.Scanner;

public class Resource {
    private final String name;

    public Resource(String name) {
        this.name = name;
    }

    public InputStream get() {
        return getClass().getResourceAsStream(name);
    }

    public String toString() {
        Scanner s = new Scanner(get()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }
}
