package webcodesecurity.decode;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

public class HashValidate { //기존에 저장 된 해시 파일과 텍스트 파일 값을
	
	//암호화된 해시 값과 비밀번호 파일을 해시화 한 값을 비교
    public boolean validate(String passwordText, File exHashFile) throws Exception {

        byte[] expected = Files.readAllBytes(exHashFile.toPath()); //이전 해시 값
        byte[] pwText = passwordText.getBytes();

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(pwText);
        byte[] now = messageDigest.digest(); //새로 만든 해시 값

        return Arrays.equals(expected, now);
    }
}