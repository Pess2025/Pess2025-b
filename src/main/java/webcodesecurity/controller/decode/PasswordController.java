package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import webcodesecurity.controller.decode.holder.PasswordMapHolder;

@RestController
@RequestMapping("/password")
public class PasswordController { //키 검색

    @GetMapping("/search")
    public ResponseEntity<String> searchPassword(@RequestParam("key") String key) {
        String value = PasswordMapHolder.getInstance().getPasswordMap().get(key);
        if (value == null) return ResponseEntity.status(404).body("해당 키를 찾을 수 없습니다.");
        return ResponseEntity.ok("해시된 비밀번호: " + value);
    }
}
