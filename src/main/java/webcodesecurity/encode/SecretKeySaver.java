/**
 * 웹코드보안 기말프로젝트 08팀 KeyPairManager.java
 * 키를 파일로 저장하는 코드입니다.
 * */

package webcodesecurity.encode;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

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
                System.out.printf("%02X ", b);
            }
            System.out.println();
            return secretKey; // 업캐스팅 일어나.
        }catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    public static boolean writeToFile(String filename, Key key) {
        try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))){
            oos.writeObject(key);
            return true;
        }catch(IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}
