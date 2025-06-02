package webcodesecurity.controller.decode.holder;

import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

public class AESKeyHolder {
    private static final AESKeyHolder instance = new AESKeyHolder();
    private SecretKey aesKey;

    private AESKeyHolder() {}

    public static AESKeyHolder getInstance() {
        return instance;
    }

    public void setAESKey(SecretKey key) {
        this.aesKey = key;

        //나중에 지워야함
        if (aesKey == null) {
            System.out.println("AES 키가 비어있습니다. 저장할 수 없습니다.");
            return;
        }
        String filePath = System.getProperty("user.dir") + "/src/main/java/webcodesecurity/output/aes.key";
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(aesKey);
            System.out.println("AES 키가 파일에 저장되었습니다: " + filePath);
        } catch (IOException e) {
            System.err.println("AES 키 저장 실패: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public SecretKey getAESKey() {
        return aesKey;
    }
}
