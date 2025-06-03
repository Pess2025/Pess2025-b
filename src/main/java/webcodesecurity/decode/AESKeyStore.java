package webcodesecurity.decode;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class AESKeyStore {

    private static final String AES_KEY_PATH = "output/aes.key";

    // AES 키 저장
    public static void saveKey(SecretKey secretKey) throws IOException {
        Files.createDirectories(Paths.get("output"));
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(AES_KEY_PATH))) {
            oos.writeObject(secretKey);
        }
    }

    // AES 키 불러오기
    public static SecretKey loadKey() throws Exception {
        File file = new File(AES_KEY_PATH);
        if (!file.exists()) {
            throw new FileNotFoundException("AES 키 파일이 존재하지 않습니다: " + AES_KEY_PATH);
        }

        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
            Object obj = ois.readObject();
            if (!(obj instanceof SecretKey)) {
                throw new IOException("올바른 SecretKey 객체가 아닙니다.");
            }
            return (SecretKey) obj;
        }
    }
}
