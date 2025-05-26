/**
 * 프론트에서 키 생성 혹은 업로드 시 호출할 컨트롤러입니다.
 * */

package webcodesecurity.controller.encode;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import webcodesecurity.encode.KeyPairManager;

import java.io.ObjectInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

@RestController
@RequestMapping("/api/keys")
public class KeyController {

    @PostMapping("/generate")
    public ResponseEntity<byte[]> generatePrivateKey() {
        KeyPair keyPair = KeyPairManager.generateKeyPair("RSA", 1024);
        if (keyPair == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"private.key\"")
                .body(privateKeyBytes);
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadPrivateKey(@RequestParam("file") MultipartFile file) {
        try {
            byte[] keyBytes = file.getBytes(); // 1. 업로드된 파일을 바이트 배열로 읽습니다.

            //  PKCS#8 포맷의 개인키로 해석할 수 있는 KeySpec 객체를 만듭니다.
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

            // 3. RSA 알고리즘을 써서 KEY factory 인스턴스를 만듭니다.
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            return ResponseEntity.ok("업로드 성공"); // 클라이언트에 전달합니다.
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("복원 실패");
        }
    }
}