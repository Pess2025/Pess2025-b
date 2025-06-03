package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import webcodesecurity.controller.decode.holder.AESKeyHolder;
import webcodesecurity.decode.FileDecode;
import webcodesecurity.decode.HashValidate;

import java.io.File;
import java.util.List;

@RestController
@RequestMapping("/verify")
public class VerifyController {

    @GetMapping("/signature")
    public ResponseEntity<String> verifySignature() {
        if (AESKeyHolder.getInstance().getAESKey() != null) {
            return ResponseEntity.ok("전자서명 유효함");
        } else {
            return ResponseEntity.status(403).body("전자서명 없음");
        }
    }

    @GetMapping("/integrity")
    public ResponseEntity<String> verifyIntegrity() {
        try {
            File txtFile = new File("output/password.txt"); //암호화 된 pw파일이라 복호화 필요

            File exHashFile = new File("output/password_hash.txt"); //해시 값

            boolean valid = new HashValidate().validate((AESKeyHolder.getInstance().getAESKey()), txtFile, exHashFile);

            /*
            // AES 복호화 → 한 줄씩 List<String>으로 가져옴
            List<String> lines = new FileDecode().decodeToLines(
                    AESKeyHolder.getInstance().getAESKey(), txtFile
            );

            // List<String> → 하나의 문자열로 합침 (줄바꿈 \n으로 했는데 값 다르면 다시 수정 해야)
            String content = String.join("\n", lines);

            */

            if (!valid) return ResponseEntity.status(403).body("검증 실패: 파일이 위조 되었습니다,");
            return ResponseEntity.ok("무결성 검증 성공");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("오류 발생: " + e.getMessage());
        }
    }
}
