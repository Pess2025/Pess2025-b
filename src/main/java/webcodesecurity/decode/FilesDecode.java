package webcodesecurity.decode;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FilesDecode {
    private static final String ENCRYPTED_FILE = "uploads/encrypted.dat";

    public List<String> decodeToLines(SecretKey secretKey) throws Exception {
        List<String> lines = new ArrayList<>();

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (
            FileInputStream f_input = new FileInputStream(ENCRYPTED_FILE);
            CipherInputStream c_input = new CipherInputStream(f_input, cipher);
        ) {
            byte[] buffer = new byte[1024]; // 한 줄 최대 길이 제한
            int idx = 0; //현재 줄 길이

            int byteValue;
            while ((byteValue = c_input.read()) != -1) {
                if ((char) byteValue == '\n') {
                    String line = new String(buffer, 0, idx, "UTF-8").trim(); //버퍼를 문자열로 변경
                    lines.add(line); //리스트에 해당 버퍼추가
                    idx = 0; // 다음 줄을 위해 초기화
                } else if ((char) byteValue != '\r') { //윈도우 줄바꿈이 \r\n이라 무시
                    if (idx < buffer.length) {
                    	buffer[idx++] = (byte) byteValue;
                    }
                }
            }
            // 마지막 줄이 \n 없이 끝났을 경우
            if (idx > 0) {
                String lastLine = new String(buffer, 0, idx, "UTF-8").trim(); //마지막 버퍼에 있는 내용도 리스트에 추가
                lines.add(lastLine);
            }
        }

        return lines;
    }
}
