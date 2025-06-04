package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import webcodesecurity.decode.AESKeyStore;
import webcodesecurity.decode.HashValidate;

import javax.crypto.SecretKey;
import java.io.File;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

@RestController
@RequestMapping("/verify")
public class VerifyController {

    @GetMapping("/time")
    public ResponseEntity<Map<String, String>> getCurrentKSTTime() {
        String kstTime = ZonedDateTime.now(ZoneId.of("Asia/Seoul"))
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        return ResponseEntity.ok(Map.of("checkTime", kstTime));
    }

    @GetMapping("/signature")
    public ResponseEntity<String> verifySignature() {

        // 전자서명 파일 존재 여부로 검증
        File sigFile = new File("output/envelope.sig");
        if (!sigFile.exists()) {
            return ResponseEntity.status(403).body("전자서명 파일이 존재하지 않음");
        }
        return ResponseEntity.ok("전자서명 존재");
    }

    @GetMapping("/integrity")
    public ResponseEntity<String> verifyIntegrity() {
        try {
            File txtFile = new File("output/password.enc"); //암호화 된 pw파일이라 복호화 필요

            File exHashFile = new File("output/password_hash.txt"); //해시 값

            SecretKey aesKey = AESKeyStore.loadKey();

            boolean valid = new HashValidate().validate(aesKey, txtFile, exHashFile);

            if (!valid) return ResponseEntity.status(403).body("검증 실패: 파일이 위조 되었습니다,");
            return ResponseEntity.ok("무결성 검증 성공");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("오류 발생: " + e.getMessage());
        }
    }
}
