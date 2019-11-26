import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECC {

	public static void main(String[] args) throws Exception {

		String plaintext = "Hello, ECC Algorithm";

		Security.addProvider(new BouncyCastleProvider());

//		KeyPair enKeyPair = generateKeyPair();
		
		byte[] privateKeyBytes = hexToByteArray("308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420c62b7ef0c85e23a844923b6ad15b2ccdadd67b3962f53cc2d868858e38e6ba6da00a06082a8648ce3d030107a144034200045ec94d73aafbfd552b116d6000cc7e37541ca49611740948144c82fd84137e738414af3d0e22270f7bcadfa4f120232b98fa6d1581f81c58a7b2e3386c2ba738");
		byte[] publicKeyBytes = hexToByteArray("3059301306072a8648ce3d020106082a8648ce3d030107034200045ec94d73aafbfd552b116d6000cc7e37541ca49611740948144c82fd84137e738414af3d0e22270f7bcadfa4f120232b98fa6d1581f81c58a7b2e3386c2ba738");
		KeyFactory kf = KeyFactory.getInstance("EC");
		PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
		PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));		
		
		byte[] cipherBytes = encrypt(publicKey, plaintext);
		System.out.println("cipher=" + byteArrayToHex(cipherBytes));
		
		byte[] plainBytes = decrypt(privateKey, cipherBytes);
		System.out.println("plain=" + new String(plainBytes));
	}
	
	public static KeyPair generateKeyPair() throws Exception {

		KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
		ecKeyGen.initialize(new ECGenParameterSpec("secp256k1")); // EC curve selection

		KeyPair ecKeyPair = ecKeyGen.generateKeyPair();

//		System.out.println("pub=" + byteArrayToHex(ecKeyPair.getPublic().getEncoded()));
//		System.out.println("pri=" + byteArrayToHex(ecKeyPair.getPrivate().getEncoded()));

		return ecKeyPair;
	}
	
	public static byte[] encrypt(PublicKey publicKey, String plaintext) throws Exception {

		Cipher iesCipher = Cipher.getInstance("ECIES",BouncyCastleProvider.PROVIDER_NAME);
		
//		iesCipher.init(Cipher.ENCRYPT_MODE, ecKeyPair.getPublic());
		iesCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		
		return iesCipher.doFinal(plaintext.getBytes());
	}
	
	public static byte[] decrypt(PrivateKey privateKey, byte[] cipherBytes) throws Exception {

		Cipher iesCipher = Cipher.getInstance("ECIES",BouncyCastleProvider.PROVIDER_NAME);
		
//		iesCipher.init(Cipher.DECRYPT_MODE, ecKeyPair.getPrivate());
		iesCipher.init(Cipher.DECRYPT_MODE, privateKey);
		
		return iesCipher.doFinal(cipherBytes);
	}

	public static byte[] hexToByteArray(String hex) {

		if (hex == null || hex.length() == 0) return null;

		byte[] ba = new byte[hex.length() / 2];

		for (int i = 0; i < ba.length; i++)
			ba[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);

		return ba;
	}

	public static String byteArrayToHex(byte[] ba) {

		if (ba == null || ba.length == 0) return null;

		StringBuffer sb = new StringBuffer(ba.length * 2);
		String hexNumber;

		for (int x = 0; x < ba.length; x++) {
			hexNumber = "0" + Integer.toHexString(0xff & ba[x]);
			sb.append(hexNumber.substring(hexNumber.length() - 2));
		}

		return sb.toString();
	}
}
