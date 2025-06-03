package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import webcodesecurity.controller.decode.holder.AESKeyHolder;
import webcodesecurity.decode.AESKeyStore;

import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/decode")
public class CheckAESController {

    @GetMapping("/check-aes-key")
    public ResponseEntity<Map<String, Boolean>> checkAESKey() throws Exception {
        Map<String, Boolean> result = new HashMap<>();
        boolean exists = false;

        try {
            SecretKey key = AESKeyStore.loadKey();
            exists = key != null;
        } catch (Exception e) {
            exists = false;
        }

        result.put("aesKeyExists", exists);
        return ResponseEntity.ok(result);
    }
}
