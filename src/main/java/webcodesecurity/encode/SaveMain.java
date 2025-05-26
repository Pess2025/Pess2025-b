package webcodesecurity.encode;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class SaveMain {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        // 키 생성. KeyPairManager class에 있는 함수 호출
        KeyPair keypair = KeyPairManager.generateKeyPair("RSA", 1024);

        // 키 가져옴. getPublic() 이런 식으로.
        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        // 공개키 출력
        System.out.println("암호화 알고리즘: " + publicKey.getAlgorithm());
        System.out.println("생성된 공개키 정보:");
        System.out.println("키의 길이 (bytes) : " + publicKey.getEncoded().length);

        byte[] publicKeyEncoded = publicKey.getEncoded();
        for(byte b : publicKeyEncoded) {
            System.out.printf("%02X ", b);
        }
        System.out.println();

        // 비밀키 출력
        System.out.println("생성된 비밀키 정보:" + privateKey.getEncoded().length);
        System.out.println("키의 길이 (bytes) : " + privateKey.getAlgorithm());

        byte[] privateKeyEncoded = privateKey.getEncoded();
        for(byte b : privateKeyEncoded) {
            System.out.printf("%02X ", b);
        }
        System.out.println();

        // 저장할 파일 이름 입력받고, 저장
        System.out.println("공개키를 저장한 파일 이름: ");
        String publicFileName = sc.next();
        System.out.println("비밀키를 저장한 파일 이름: ");
        String privateFileName = sc.next();

        SecretKeySaver.writeToFile(publicFileName, publicKey);
        SecretKeySaver.writeToFile(privateFileName, privateKey);

        System.out.println("성공적으로 저장되었습니다.");
        sc.close();
    }

}
