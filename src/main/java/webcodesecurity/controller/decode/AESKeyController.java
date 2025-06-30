package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import webcodesecurity.decode.AESKeyStore;
import webcodesecurity.decode.EnvelopeDecode;

import javax.crypto.SecretKey;
import java.io.File;

@RestController
@RequestMapping("/api/keys")
public class AESKeyController { //비밀키로 대칭키 복호화

    @PostMapping("/decode/upload")
    public ResponseEntity<String> uploadPrivateKey(@RequestParam("file") MultipartFile privateKey) {
        try {
            String envelopePath = "output/aes_key_encrypted.bin";
            File envelopeFile = new File(envelopePath);

            SecretKey aesKey = new EnvelopeDecode().getAESKeyFromEnvelope(privateKey, envelopeFile);
            AESKeyStore.saveKey(aesKey);
            return ResponseEntity.ok("개인 키 업로드 성공");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("실패: 암호화 시에 사용한 PrivateKey가 아닙니다.");
        }
    }
}
