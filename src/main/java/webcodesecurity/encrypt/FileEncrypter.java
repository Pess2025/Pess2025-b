/**
 * 파일명 : FileEncrypter.jsx
 * 설명 : 파일을 AES로 암호화합니다.
 * 작성자 : 정여진
 * 작성일 : 2025.05.26.
 * */
package webcodesecurity.encrypt;

import webcodesecurity.controller.encode.holder.AESKeyHolder;
import webcodesecurity.key.SecretKeySaver;

import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class FileEncrypter {

    public static SecretKey encryptFile(String inputFilePath, String outputFilePath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        System.out.println("[DEBUG] FileEncrypter.encryptFile 호출됨");
        System.out.println("[DEBUG] 평문 파일: " + inputFilePath);
        System.out.println("[DEBUG] 암호문 저장 경로: " + new File(outputFilePath).getAbsolutePath());

        //1. AES 대칭키를 만듭니다.
//        SecretKey secretKey = (SecretKey) SecretKeySaver.generateKey("AES", 128);
        SecretKey secretKey = AESKeyHolder.getInstance().getAESKey();

        //2. AES Cipher를 초기화합니다.
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        //3. 파일을 읽고 암호화 후 저장합니다.
        try (FileInputStream fis = new FileInputStream(inputFilePath);
             FileOutputStream fos = new FileOutputStream(outputFilePath)) {

            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) fos.write(output);
            }

            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null) fos.write(finalBytes);

            Arrays.fill(buffer, (byte) 0); // 메모리 덤프를 막기 위해 평문 메모리는 지워야한다.0으로

        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } // 이 부분 catch문을 이렇게 작성하는 게 맞나? 나중에 코드리뷰 때 다시 확인할 것.

        return secretKey;
    }

    public static boolean encryptBytes(SecretKey aes, byte[] input, File outputFile) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aes);


        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            byte[] encrypted = cipher.doFinal(input);
            fos.write(encrypted);
            return true; // 정상 처리 완료 시
        } catch (Exception e) {
            e.printStackTrace();
            return false;         // 예외 발생 시 false 반환
        }

    }

}
