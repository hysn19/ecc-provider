# ecc-provider
ecc 암호화 및 서명검증 테스트 코드


```java
String plaintext = "Hello, ECC Algorithm";

Security.addProvider(new BouncyCastleProvider());

// KeyPair enKeyPair = generateKeyPair();
byte[] privateKeyBytes = hexToByteArray("308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420c62b7ef0c85e23a844923b6ad15b2ccdadd67b3962f53cc2d868858e38e6ba6da00a06082a8648ce3d030107a144034200045ec94d73aafbfd552b116d6000cc7e37541ca49611740948144c82fd84137e738414af3d0e22270f7bcadfa4f120232b98fa6d1581f81c58a7b2e3386c2ba738");

byte[] publicKeyBytes = hexToByteArray("3059301306072a8648ce3d020106082a8648ce3d030107034200045ec94d73aafbfd552b116d6000cc7e37541ca49611740948144c82fd84137e738414af3d0e22270f7bcadfa4f120232b98fa6d1581f81c58a7b2e3386c2ba738");

KeyFactory kf = KeyFactory.getInstance("EC");
PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));		

byte[] cipherBytes = encrypt(publicKey, plaintext);
byte[] plainBytes = decrypt(privateKey, cipherBytes);
```


```java
SignatureVerifyTest test = new SignatureVerifyTest();

test.setPublicKey("eyJrdHkiOiJSU0EiLCJhbGciOiJSUzI1NiIsIm4iOiJ0NjhrcTNfYW1lT0lSRGRENzdoeHNzM1l2S2xlR3BxWTY0NGdIZE1jTG9zRXhKT1dQS3BjVGx6ajgwSGEtVHEyN3ZTSkQ4NFc3VldHcXhNRUlCNVl0NDFvVFZsT1dqUnFBeTROYmdBR3pXTGFJa2pkVk9pYU1tMU9DZ052THBlUXBRbG1FYlByckVfcERpRGNtbnhRZW1vMnZmNkxMeENBajR2OUlmb0cxVGFveTZuMTcyeDdqOFFkZXNOY1VHdzF3R1lhZnRPSEg2STM0V1hzaUtReHpCNEhFTlNSZUl3Mm9ib1gxeUlELVZzcnZndWw5QURWRzRoSTV1RWZVQm9Wa1F6aFhPUFRHREtOMTV3dkxtNERXSlJuUTRuY0xwX0V3YWdJc3JiOG9pZGtLN09KUkg0VjlpYmg2NzhWdzVRX19aRFh5dF9PbVgxbjM5Y1BhOXNwb3ciLCJlIjoiQVFBQiJ9");
        
test.setSignature("icri7j2YhTeThXpTvi8bgDW6ewYgV75xpT-4iOqFWAvebp35QAMlE3qj1Zvq0oVVuXMjwZq1h06kCXqRrXzkc6zy1ia5YqM0vMVupRZ7MyDlMewtiXvvMdvLB6zyL9gs9D62wJlkbPJGY_m0vbojm4_3bST3NDtXMVsEzXUb89VROX4oMLEtyy5vftQVHIy3-3OMIIbrMDzRrLmfZuoe4qL820EGTO0WAITVYdNJr-sotAgGcJuc7yNqKT9ktWyHPFyfN5Sxyrv1EcTc20akeUY1y9inMTut3awLDVcaIo3xgVpowXuZuvM_UPZelhmSvrmMoQCBhLRrNrnjswLnAw");
		test.setPlainText("2d92da1753e375c7ae988c483dc4082b986a9514d6e0ff54e33b0234f1871f210500000002a08f4755062baf68524f8d9d040aac520728cd2a87f70a1117982d56feafa67b");

System.out.println("Signature verify : " + test.verify());
```
