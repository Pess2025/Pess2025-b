/**
 * 서버의공개키입니다.
 * */

package webcodesecurity.key;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;

@Component
public class KeyInitializer {

    private final String KEY_DIR = "keys";
    private final String PRIVATE_KEY_PATH = KEY_DIR + "/private.key";
    private final String PUBLIC_KEY_PATH = KEY_DIR + "/public.key";

    @PostConstruct
    public void initKeys() {
        try {
            File keyDir = new File(KEY_DIR);
            if (!keyDir.exists()) keyDir.mkdirs();

            File privateKeyFile = new File(PRIVATE_KEY_PATH);
            File publicKeyFile = new File(PUBLIC_KEY_PATH);

            if (privateKeyFile.exists() && publicKeyFile.exists()) {
                System.out.println("[KeyInitializer] 이미 키 파일이 존재합니다.");
                return;
            }

            KeyPair keyPair = KeyPairManager.generateKeyPair("RSA", 1024);
            if (keyPair == null) {
                throw new IllegalStateException("KeyPair 생성 실패");
            }

            // 직렬화된 키 저장 (수업 기반)
            try (ObjectOutputStream out1 = new ObjectOutputStream(new FileOutputStream(privateKeyFile))) {
                out1.writeObject(keyPair.getPrivate());
            }

            try (ObjectOutputStream out2 = new ObjectOutputStream(new FileOutputStream(publicKeyFile))) {
                out2.writeObject(keyPair.getPublic());
            }

            System.out.println("[KeyInitializer] RSA 키 쌍 자동 생성 완료");
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("초기 키 생성 실패", e);
        }
    }
}
