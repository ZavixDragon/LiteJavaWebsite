package litejavawebsite;

public class FileExtension {
    private final String fileName;

    public FileExtension(String fileName) {
        this.fileName = fileName;
    }

    public String get() {
        int extensionIndex = fileName.lastIndexOf('.');
        return extensionIndex == 0 ? fileName : fileName.substring(extensionIndex + 1);
    }
}
