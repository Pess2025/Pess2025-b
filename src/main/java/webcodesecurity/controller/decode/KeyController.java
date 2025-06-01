package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import webcodesecurity.decode.EnvelopeDecode;
import webcodesecurity.controller.decode.holder.AESKeyHolder;

import javax.crypto.SecretKey;
import java.io.File;

@RestController
@RequestMapping("/key")
public class KeyController { //비밀키로 대칭키 복호화

    @PostMapping("/upload-private")
    public ResponseEntity<String> uploadPrivateKey(@RequestParam("privateKey") MultipartFile privateKey,
                                                   @RequestParam("envelope") MultipartFile envelope) {
        try {
            File keyFile = new File("uploads/private.key");
            File envelopeFile = new File("uploads/envelope.dat");
            privateKey.transferTo(keyFile);
            envelope.transferTo(envelopeFile);

            SecretKey aesKey = new EnvelopeDecode().getAESKeyFromEnvelope(keyFile, envelopeFile);
            AESKeyHolder.getInstance().setAESKey(aesKey);
            return ResponseEntity.ok("대칭키 획득 성공");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("실패: " + e.getMessage());
        }
    }
}
