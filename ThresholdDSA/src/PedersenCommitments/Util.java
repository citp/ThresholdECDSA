package PedersenCommitments;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Util {

	/**
	 * We generate an order q cyclic group. To do this, we find a Sophie Germain
	 * prime and use that as q. p, the modulus is set to 2*q+1.
	 * 
	 * <p>
	 * The order q subgroup of quadratic residues is cyclic and of prime order,
	 * and every element in it is a generator. To get a generator of this
	 * subgroup, we can choose any element in Z^p and then square it, thus
	 * ensuring that we have an element in the order q subgroup.
	 * 
	 * <p>
	 * Moreover, we do this process verifiably. We seed our random numbeer
	 * generator with the sha-256 hash of the provided string
	 * {@code verifiableStartString}.
	 * 
	 * @param qBitLength
	 *            The number of bits in the order of the cyclic group
	 * @param verifiableStartString
	 * @return
	 */
	public static PedersenPublicParams<BigInteger> generatePedersenParams(
			String filename, int qBitLength, String verifiableStartString) {
		byte[] verifiableSeed = thresholdDSA.Util
				.sha256Hash(verifiableStartString.getBytes());
		SecureRandom rand = new SecureRandom(verifiableSeed);
		BigInteger q = BigInteger.probablePrime(qBitLength, rand);
		while (!q.add(q).add(BigInteger.ONE).isProbablePrime(100)) {
			q = BigInteger.probablePrime(qBitLength, rand);
		}
		BigInteger p = q.add(q).add(BigInteger.ONE);
		BigInteger g = thresholdDSA.Util.randomFromZn(p, rand).pow(2);
		BigInteger h = thresholdDSA.Util.randomFromZn(p, rand).pow(2);

		PedersenPublicParams<BigInteger> params = new PedersenPublicParams<BigInteger>(
				q, p, g, h);

		// write it to the file
		try {
			FileOutputStream fos = new FileOutputStream(filename);
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(params);
			oos.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Cannot write Pedersen params to file");
			e.printStackTrace();
		}

		return params;
	}
	
	
	public static PedersenPublicParams<BigInteger> generatePedersenParamsFromInternet(
			String filename, String verifiableStartString) {
		byte[] verifiableSeed = thresholdDSA.Util
				.sha256Hash(verifiableStartString.getBytes());
		SecureRandom rand = new SecureRandom(verifiableSeed);
		
		// took strong from http://cypherpunks.venona.com/date/1995/11/msg00682.html and checked
		// the strong primality myself
		byte[] bytes ={(byte) 0xFE,(byte) 0xEA,(byte) 0xD1,(byte) 0x9D,(byte) 0xBE,(byte) 0xAF,(byte) 0x90,(byte) 0xF6,(byte) 0x1C,(byte) 0xFC,(byte) 0xA1,(byte) 0x06,
		        (byte) 0x5D,(byte) 0x69,(byte) 0xDB,(byte) 0x08,(byte) 0x83,(byte) 0x9A,(byte) 0x2A,(byte) 0x2B,(byte) 0x6A,(byte) 0xEF,(byte) 0x24,(byte) 0x88,
		        (byte) 0xAB,(byte) 0xD7,(byte) 0x53,(byte) 0x1F,(byte) 0xBB,(byte) 0x3E,(byte) 0x46,(byte) 0x2E,(byte) 0x7D,(byte) 0xCE,(byte) 0xCE,(byte) 0xFB,
		        (byte) 0xCE,(byte) 0xDC,(byte) 0xBB,(byte) 0xBD,(byte) 0xF5,(byte) 0x65,(byte) 0x49,(byte) 0xEE,(byte) 0x95,(byte) 0x15,(byte) 0x30,(byte) 0x56,
		        (byte) 0x81,(byte) 0x88,(byte) 0xC3,(byte) 0xD9,(byte) 0x72,(byte) 0x94,(byte) 0x16,(byte) 0x6B,(byte) 0x6A,(byte) 0xAB,(byte) 0xA0,(byte) 0xAA,
		        (byte) 0x5C,(byte) 0xC8,(byte) 0x55,(byte) 0x5F,(byte) 0x91,(byte) 0x25,(byte) 0x50,(byte) 0x3A,(byte) 0x18,(byte) 0x0E,(byte) 0x90,(byte) 0x32,
		        (byte) 0x4C,(byte) 0x7F,(byte) 0x39,(byte) 0xC6,(byte) 0xA3,(byte) 0x45,(byte) 0x2F,(byte) 0x31,(byte) 0x42,(byte) 0xEE,(byte) 0x72,(byte) 0xAB,
		        (byte) 0x7D,(byte) 0xFF,(byte) 0xC7,(byte) 0x4C,(byte) 0x52,(byte) 0x8D,(byte) 0xB6,(byte) 0xDA,(byte) 0x76,(byte) 0xD9,(byte) 0xC6,(byte) 0x44,
		        (byte) 0xF5,(byte) 0x5D,(byte) 0x08,(byte) 0x3E,(byte) 0x9C,(byte) 0xDE,(byte) 0x74,(byte) 0xF7,(byte) 0xE7,(byte) 0x42,(byte) 0x41,(byte) 0x3B,
		        (byte) 0x69,(byte) 0x47,(byte) 0x66,(byte) 0x17,(byte) 0xD2,(byte) 0x67,(byte) 0x0F,(byte) 0x2B,(byte) 0xF6,(byte) 0xD5,(byte) 0x9F,(byte) 0xFC,
		        (byte) 0xD7,(byte) 0xC3,(byte) 0xBD,(byte) 0xDE,(byte) 0xED,(byte) 0x41,(byte) 0xE2,(byte) 0xBD,(byte) 0x2C,(byte) 0xCD,(byte) 0xD9,(byte) 0xE6,
		        (byte) 0x12,(byte) 0xF1,(byte) 0x05,(byte) 0x6C,(byte) 0xAB,(byte) 0x88,(byte) 0xC4,(byte) 0x41,(byte) 0xD7,(byte) 0xF9,(byte) 0xBA,(byte) 0x74,
		        (byte) 0x65,(byte) 0x1E,(byte) 0xD1,(byte) 0xA8,(byte) 0x4D,(byte) 0x40,(byte) 0x7A,(byte) 0x27,(byte) 0xD7,(byte) 0x18,(byte) 0x95,(byte) 0xF7,
		        (byte) 0x77,(byte) 0xAB,(byte) 0x6C,(byte) 0x77,(byte) 0x63,(byte) 0xCC,(byte) 0x00,(byte) 0xE6,(byte) 0xF1,(byte) 0xC3,(byte) 0x0B,(byte) 0x2F,
		        (byte) 0xE7,(byte) 0x94,(byte) 0x46,(byte) 0x92,(byte) 0x7E,(byte) 0x74,(byte) 0xBC,(byte) 0x73,(byte) 0xB8,(byte) 0x43,(byte) 0x1B,(byte) 0x53,
		        (byte) 0x01,(byte) 0x1A,(byte) 0xF5,(byte) 0xAD,(byte) 0x15,(byte) 0x15,(byte) 0xE6,(byte) 0x3D,(byte) 0xC1,(byte) 0xDE,(byte) 0x83,(byte) 0xCC,
		        (byte) 0x80,(byte) 0x2E,(byte) 0xCE,(byte) 0x7D,(byte) 0xFC,(byte) 0x71,(byte) 0xFB,(byte) 0xDF,(byte) 0x17,(byte) 0x9F,(byte) 0x8E,(byte) 0x41,
		        (byte) 0xD7,(byte) 0xF1,(byte) 0xB4,(byte) 0x3E,(byte) 0xBA,(byte) 0x75,(byte) 0xD5,(byte) 0xA9,(byte) 0xC3,(byte) 0xB1,(byte) 0x1D,(byte) 0x4F,
		        (byte) 0x1B,(byte) 0x0B,(byte) 0x5A,(byte) 0x09,(byte) 0x88,(byte) 0xA9,(byte) 0xAA,(byte) 0xCB,(byte) 0xCC,(byte) 0xC1,(byte) 0x05,(byte) 0x12,
		        (byte) 0x26,(byte) 0xDC,(byte) 0x84,(byte) 0x10,(byte) 0xE4,(byte) 0x16,(byte) 0x93,(byte) 0xEC,(byte) 0x85,(byte) 0x91,(byte) 0xE3,(byte) 0x1E,
		        (byte) 0xE2,(byte) 0xF5,(byte) 0xAF,(byte) 0xDF,(byte) 0xAE,(byte) 0xDE,(byte) 0x12,(byte) 0x2D,(byte) 0x12,(byte) 0x77,(byte) 0xFC,(byte) 0x27,
		        (byte) 0x0B,(byte) 0xE4,(byte) 0xD2,(byte) 0x5C,(byte) 0x11,(byte) 0x37,(byte) 0xA5,(byte) 0x8B,(byte) 0xE9,(byte) 0x61,(byte) 0xEA,(byte) 0xC9,
		        (byte) 0xF2,(byte) 0x7D,(byte) 0x4C,(byte) 0x71,(byte) 0xE2,(byte) 0x39,(byte) 0x19,(byte) 0x04,(byte) 0xDD,(byte) 0x6A,(byte) 0xB2,(byte) 0x7B,
		        (byte) 0xEC,(byte) 0xE5,(byte) 0xBD,(byte) 0x6C,(byte) 0x64,(byte) 0xC7,(byte) 0x9B,(byte) 0x14,(byte) 0x6C,(byte) 0x2D,(byte) 0x20,(byte) 0x8C,
		        (byte) 0xD6,(byte) 0x3A,(byte) 0x4B,(byte) 0x74,(byte) 0xF8,(byte) 0xDA,(byte) 0xE6,(byte) 0x38,(byte) 0xDB,(byte) 0xE2,(byte) 0xC8,(byte) 0x80,
		        (byte) 0x6B,(byte) 0xA1,(byte) 0x07,(byte) 0x73,(byte) 0x8A,(byte) 0x8D,(byte) 0xF5,(byte) 0xCF,(byte) 0xE2,(byte) 0x14,(byte) 0xA4,(byte) 0xB7,
		        (byte) 0x3D,(byte) 0x03,(byte) 0xC9,(byte) 0x12,(byte) 0x75,(byte) 0xFB,(byte) 0xA5,(byte) 0x72,(byte) 0x81,(byte) 0x46,(byte) 0xCE,(byte) 0x5F,
		        (byte) 0xEC,(byte) 0x01,(byte) 0x77,(byte) 0x5B,(byte) 0x74,(byte) 0x48,(byte) 0x1A,(byte) 0xDF,(byte) 0x86,(byte) 0xF4,(byte) 0x85,(byte) 0x4D,
		        (byte) 0x65,(byte) 0xF5,(byte) 0xDA,(byte) 0x4B,(byte) 0xB6,(byte) 0x7F,(byte) 0x88,(byte) 0x2A,(byte) 0x60,(byte) 0xCE,(byte) 0x0B,(byte) 0xCA,
		        (byte) 0x0A,(byte) 0xCD,(byte) 0x15,(byte) 0x7A,(byte) 0xA3,(byte) 0x77,(byte) 0xF1,(byte) 0x0B,(byte) 0x09,(byte) 0x1A,(byte) 0xD0,(byte) 0xB5,
		        (byte) 0x68,(byte) 0x89,(byte) 0x30,(byte) 0x39,(byte) 0xEC,(byte) 0xA3,(byte) 0x3C,(byte) 0xDC,(byte) 0xB6,(byte) 0x1B,(byte) 0xA8,(byte) 0xC9,
		        (byte) 0xE3,(byte) 0x2A,(byte) 0x87,(byte) 0xA2,(byte) 0xF5,(byte) 0xD8,(byte) 0xB7,(byte) 0xFD,(byte) 0x26,(byte) 0x73,(byte) 0x4D,(byte) 0x2F,
		        (byte) 0x09,(byte) 0x67,(byte) 0x92,(byte) 0x35,(byte) 0x2D,(byte) 0x70,(byte) 0xAD,(byte) 0xE9,(byte) 0xF4,(byte) 0xA5,(byte) 0x1D,(byte) 0x84,
		        (byte) 0x88,(byte) 0xBC,(byte) 0x57,(byte) 0xD3,(byte) 0x2A,(byte) 0x63,(byte) 0x8E,(byte) 0x0B,(byte) 0x14,(byte) 0xD6,(byte) 0x69,(byte) 0x3F,
		        (byte) 0x67,(byte) 0x76,(byte) 0xFF,(byte) 0xFB,(byte) 0x35,(byte) 0x5F,(byte) 0xED,(byte) 0xF6,(byte) 0x52,(byte) 0x20,(byte) 0x1F,(byte) 0xA7,
		        (byte) 0x0C,(byte) 0xB8,(byte) 0xDB,(byte) 0x34,(byte) 0xFB,(byte) 0x54,(byte) 0x94,(byte) 0x90,(byte) 0x95,(byte) 0x1A,(byte) 0x70,(byte) 0x1E,
		        (byte) 0x04,(byte) 0xAD,(byte) 0x49,(byte) 0xD6,(byte) 0x71,(byte) 0xB7,(byte) 0x4D,(byte) 0x08,(byte) 0x9C,(byte) 0xAA,(byte) 0x8C,(byte) 0x0E,
		        (byte) 0x5E,(byte) 0x83,(byte) 0x3A,(byte) 0x21,(byte) 0x29,(byte) 0x1D,(byte) 0x69,(byte) 0x78,(byte) 0xF9,(byte) 0x18,(byte) 0xF2,(byte) 0x5D,
		        (byte) 0x5C,(byte) 0x76,(byte) 0x9B,(byte) 0xDB,(byte) 0xE4,(byte) 0xBB,(byte) 0x72,(byte) 0xA8,(byte) 0x4A,(byte) 0x1A,(byte) 0xFE,(byte) 0x6A,
		        (byte) 0x0B,(byte) 0xBA,(byte) 0xD1,(byte) 0x8D,(byte) 0x3E,(byte) 0xAC,(byte) 0xC7,(byte) 0xB4,(byte) 0x54,(byte) 0xAF,(byte) 0x40,(byte) 0x8D,
		        (byte) 0x4F,(byte) 0x1C,(byte) 0xCB,(byte) 0x23,(byte) 0xB9,(byte) 0xAE,(byte) 0x57,(byte) 0x6F,(byte) 0xDA,(byte) 0xE2,(byte) 0xD1,(byte) 0xA6,
		        (byte) 0x8F,(byte) 0x43,(byte) 0xD2,(byte) 0x75,(byte) 0x74,(byte) 0x1D,(byte) 0xB1,(byte) 0x9E,(byte) 0xED,(byte) 0xC3,(byte) 0xB8,(byte) 0x1B,
				(byte) 0x5E, (byte) 0x56, (byte) 0x96, (byte) 0x4F,
				(byte) 0x5F, (byte) 0x8C, (byte) 0x33, (byte) 0x63,
		        };
		
		BigInteger p = new BigInteger(1,bytes);
		BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
		
		BigInteger g = thresholdDSA.Util.randomFromZn(p, rand).pow(2);
		BigInteger h = thresholdDSA.Util.randomFromZn(p, rand).pow(2);

		PedersenPublicParams<BigInteger> params = new PedersenPublicParams<BigInteger>(
				q, p, g, h);
		// write it to the file
		try {
			FileOutputStream fos = new FileOutputStream(filename);
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(params);
			oos.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Cannot write Pedersen params to file");
			e.printStackTrace();
		}

		return params;
	}
	


	public static PedersenPublicParams<BigInteger> readPedersenParams(
			String filename) throws IOException, ClassNotFoundException {
		FileInputStream fis = new FileInputStream(filename);
		BufferedInputStream bis = new BufferedInputStream(fis);
		ObjectInputStream ois = new ObjectInputStream(bis);
		@SuppressWarnings("unchecked")
		PedersenPublicParams<BigInteger> params = (PedersenPublicParams<BigInteger>) ois
				.readObject();
		ois.close();
		return params;

	}
	
	

}
