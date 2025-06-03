package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import webcodesecurity.controller.decode.holder.AESKeyHolder;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/decode")
public class CheckAESController {

    @GetMapping("/check-aes-key")
    public ResponseEntity<Map<String, Boolean>> checkAESKey() {
        Map<String, Boolean> result = new HashMap<>();
        result.put("aesKeyExists", AESKeyHolder.getInstance().hasAESKey());
        return ResponseEntity.ok(result);
    }
}
