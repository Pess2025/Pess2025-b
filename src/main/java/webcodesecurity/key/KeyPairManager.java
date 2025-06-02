/**
 * 웹코드보안 기말프로젝트 08팀 KeyPairManager.java
 * 1. key pair 생성 class입니다.
 * */
package webcodesecurity.key;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyPairManager {
    public static KeyPair generateKeyPair(String algorithm, int keyLength) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
            kpg.initialize(keyLength);
            KeyPair keypair = kpg.generateKeyPair();

            return keypair;
        } catch (NoSuchAlgorithmException e) {

            e.printStackTrace();
            return null;
        }
    }

}
