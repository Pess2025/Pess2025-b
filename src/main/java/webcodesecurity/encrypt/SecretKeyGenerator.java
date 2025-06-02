/**
 * 파일명 : SecretKeyGenerator.jsx
 * 설명 : 파일을 AES로 암호화합니다.
 * 작성자 : 정여진
 * 작성일 : 2025.06.02.
 * */
package webcodesecurity.encrypt;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SecretKeyGenerator {
    /**
     * AES 대칭키를 생성합니다.
     *
     * @param keySize 키 길이 => 256
     * @return 생성된 SecretKey 객체
     * @throws Exception 예외가 발생할 때.
     */
    public static SecretKey generateAESKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); //AES 사용
        keyGen.init(keySize);
        return keyGen.generateKey();
    }
}
