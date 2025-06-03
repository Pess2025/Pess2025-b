package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import webcodesecurity.decode.EnvelopeDecode;
import webcodesecurity.controller.decode.holder.AESKeyHolder;

import javax.crypto.SecretKey;
import java.io.File;
import java.security.PrivateKey;

@RestController
@RequestMapping("/api/keys")
public class AESKeyController { //비밀키로 대칭키 복호화

    @PostMapping("/decode/upload")
    public ResponseEntity<String> uploadPrivateKey(@RequestParam("privateKey") MultipartFile privateKey) {
        try {
            String envelopePath = System.getProperty("user.dir") + "/output/aes_key_encrypted.bin";
            File envelopeFile = new File(envelopePath);

            //privateKey 서버에 저장 하지 않고 메모리에 있는 것을 사용하기 위해 inputStream만 전달 privateKey.getInputStream()
            SecretKey aesKey = new EnvelopeDecode().getAESKeyFromEnvelope(privateKey, envelopeFile);
            AESKeyHolder.getInstance().setAESKey(aesKey);
            return ResponseEntity.ok("개인 키 업로드 성공");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("실패: " + e.getMessage());
        }
    }
}
