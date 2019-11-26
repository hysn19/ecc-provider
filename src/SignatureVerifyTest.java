import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.JsonWebKey;

public class SignatureVerifyTest {

	private PublicKey publicKey;
	private byte[] signature;
	private byte[] plainText;

	public static void main(String args[]) throws Exception {

		SignatureVerifyTest test = new SignatureVerifyTest();

		test.setPublicKey(
				"eyJrdHkiOiJSU0EiLCJhbGciOiJSUzI1NiIsIm4iOiJ0NjhrcTNfYW1lT0lSRGRENzdoeHNzM1l2S2xlR3BxWTY0NGdIZE1jTG9zRXhKT1dQS3BjVGx6ajgwSGEtVHEyN3ZTSkQ4NFc3VldHcXhNRUlCNVl0NDFvVFZsT1dqUnFBeTROYmdBR3pXTGFJa2pkVk9pYU1tMU9DZ052THBlUXBRbG1FYlByckVfcERpRGNtbnhRZW1vMnZmNkxMeENBajR2OUlmb0cxVGFveTZuMTcyeDdqOFFkZXNOY1VHdzF3R1lhZnRPSEg2STM0V1hzaUtReHpCNEhFTlNSZUl3Mm9ib1gxeUlELVZzcnZndWw5QURWRzRoSTV1RWZVQm9Wa1F6aFhPUFRHREtOMTV3dkxtNERXSlJuUTRuY0xwX0V3YWdJc3JiOG9pZGtLN09KUkg0VjlpYmg2NzhWdzVRX19aRFh5dF9PbVgxbjM5Y1BhOXNwb3ciLCJlIjoiQVFBQiJ9");
		test.setSignature(
				"icri7j2YhTeThXpTvi8bgDW6ewYgV75xpT-4iOqFWAvebp35QAMlE3qj1Zvq0oVVuXMjwZq1h06kCXqRrXzkc6zy1ia5YqM0vMVupRZ7MyDlMewtiXvvMdvLB6zyL9gs9D62wJlkbPJGY_m0vbojm4_3bST3NDtXMVsEzXUb89VROX4oMLEtyy5vftQVHIy3-3OMIIbrMDzRrLmfZuoe4qL820EGTO0WAITVYdNJr-sotAgGcJuc7yNqKT9ktWyHPFyfN5Sxyrv1EcTc20akeUY1y9inMTut3awLDVcaIo3xgVpowXuZuvM_UPZelhmSvrmMoQCBhLRrNrnjswLnAw");
		test.setPlainText(
				"2d92da1753e375c7ae988c483dc4082b986a9514d6e0ff54e33b0234f1871f210500000002a08f4755062baf68524f8d9d040aac520728cd2a87f70a1117982d56feafa67b");

		System.out.println("Signature verify : " + test.verify());
	}

	public void setPublicKey(String pk) throws Exception {
		
		String pubKey = Base64Url.decodeToUtf8String(pk);
		JsonWebKey jwk = JsonWebKey.Factory.newJwk(pubKey);
		publicKey = (PublicKey) jwk.getKey();
	}

	public void setSignature(String s) {
		
		this.signature = Base64Url.decode(s);
	}

	public void setPlainText(String p) {
		
		this.plainText = hexToByteArray(p);
	}

	public boolean verify() throws Exception {
		
		Security.addProvider(new BouncyCastleProvider());
		
		Signature sig = Signature.getInstance("SHA256withRSA", "BC");
		sig.initVerify(publicKey);
		sig.update(plainText);
		
		return sig.verify(signature);
	}

	// hex to byte[]
	public static byte[] hexToByteArray(String hex) {
		
		if (hex == null || hex.length() == 0)
			return null;

		byte[] ba = new byte[hex.length() / 2];
		
		for (int i = 0; i < ba.length; i++)
			ba[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
		
		return ba;
	}

	// byte[] to hex
	public static String byteArrayToHex(byte[] ba) {
		
		if (ba == null || ba.length == 0)
			return null;
		
		StringBuffer sb = new StringBuffer(ba.length * 2);
		String hexNumber;
		
		for (int x = 0; x < ba.length; x++) {
			hexNumber = "0" + Integer.toHexString(0xff & ba[x]);
			sb.append(hexNumber.substring(hexNumber.length() - 2));
		}
		
		return sb.toString();
	}
}
