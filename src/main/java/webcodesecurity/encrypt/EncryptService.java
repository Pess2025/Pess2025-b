/**
 * 파일명 : EncryptService.jsx
 * 설명 : FileEncrypter 와 EnvelopeGenerator 둘을 조합하여 암호문을 만들고
        전자봉투 생성 로직을 만듭니다.
 * 작성자 : 정여진
 * 작성일 : 2025.05.26.
 * */
package webcodesecurity.encrypt;

import javax.crypto.SecretKey;

public class EncryptService {

    /**
     * 파일 암호화와 전자봉투 생성 전체 과정을 처리하는 메서드
     *
     * @param inputFilePath 암호화할 평문 파일 경로
     * @param encryptedOutputPath 암호문을 저장할 파일 경로
     * @param publicKeyPath 공개키 파일 경로
     * @param envelopeOutputPath 전자봉투 저장 경로
     * @throws Exception 암호화 또는 전자봉투 생성 중 에러 발생 시
     */
    public static void process(String inputFilePath, String encryptedOutputPath,
                               String publicKeyPath, String envelopeOutputPath) throws Exception {

        System.out.println("[DEBUG] EncryptService 시작");
        System.out.println("[DEBUG] 입력 파일 경로: " + inputFilePath);
        System.out.println("[DEBUG] 암호문 저장 경로: " + encryptedOutputPath);
        System.out.println("[DEBUG] 공개키 경로: " + publicKeyPath);
        System.out.println("[DEBUG] 전자봉투 저장 경로: " + envelopeOutputPath);

        // 1. 파일 암호화(AES 대칭키) 하고 대칭키 return.
        SecretKey secretKey = FileEncrypter.encryptFile(inputFilePath, encryptedOutputPath);

        // 2. 전자봉투 생성 (대칭키->공개키로 암호화)
        EnvelopeGenerator.createEnvelopeFile(secretKey, publicKeyPath, envelopeOutputPath);
    }
}

