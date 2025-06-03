/**
 * 웹코드보안 기말프로젝트 08팀 KeyPairManager.java
 * 키를 파일로 저장하는 코드입니다.
 * */

package webcodesecurity.key;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SecretKeySaver {
    public static Key generateKey(String algorithm, int keylength) {
        try {
            KeyGenerator keygen = KeyGenerator.getInstance(algorithm);
            keygen.init(keylength);
            SecretKey secretKey = keygen.generateKey(); // return 타입이 Key여도, 이거는 여전히 type이 secretKey여야 한다.

            byte[] key = secretKey.getEncoded();
            for(byte b : key) {
                System.out.printf("SecretKeySaver: %02X ", b);
            }
            System.out.println();
            return secretKey; // 업캐스팅 일어나.
        }catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    public static boolean writeToFileAsPem(String filename, Key key) {
        try {
            byte[] encoded = key.getEncoded();

            String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
            String pem = "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----";

            Files.writeString(Paths.get(filename), pem);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}
