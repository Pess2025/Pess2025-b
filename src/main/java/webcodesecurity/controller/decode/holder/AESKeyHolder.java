package webcodesecurity.controller.decode.holder;

import javax.crypto.SecretKey;

public class AESKeyHolder {
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
}
