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

    @GetMapping("/integrity")
    public ResponseEntity<String> verifyIntegrity() {
        try {
            File txtFile = new File("uploads/password.txt");

            // AES 복호화 → 한 줄씩 List<String>으로 가져옴
            List<String> lines = new FileDecode().decodeToLines(
                    AESKeyHolder.getInstance().getAESKey(), txtFile
            );

            // List<String> → 하나의 문자열로 합침 (줄바꿈 \n으로 했는데 값 다르면 다시 수정 해야)
            String content = String.join("\n", lines);

            File exHashFile = new File("uploads/hash.dat");
            boolean valid = new HashValidate().validate(content, exHashFile);

            if (!valid) return ResponseEntity.status(403).body("검증 실패: 파일이 위조 되었습니다,");
            return ResponseEntity.ok("무결성 검증 성공");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("오류 발생: " + e.getMessage());
        }
    }
}
