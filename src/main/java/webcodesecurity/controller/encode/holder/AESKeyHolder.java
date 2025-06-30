package webcodesecurity.controller.encode.holder;

import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class AESKeyHolder implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final AESKeyHolder instance = new AESKeyHolder();
    private SecretKey aesKey;

    private AESKeyHolder() {}

    public static AESKeyHolder getInstance() {
        return instance;
    }

    public void setAESKey(SecretKey key) {
        this.aesKey = key;
    }

    public SecretKey getAESKey() {
        return aesKey;
    }

    public boolean hasAESKey() {
        return this.aesKey != null;
    }
}
