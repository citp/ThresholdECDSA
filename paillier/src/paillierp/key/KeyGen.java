/**
 * KeyGen.java
 */
package paillierp.key;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.io.*;

/**
 * Generates key pairs for the Paillier encryption scheme.  This set of static
 * methods creates, writes, and retrieves keys used for both the generalized
 * and threshold versions of the Paillier scheme.  Other utilities for primes
 * and factorials are included.
 * 
 * <h3>Generalized Paillier Key Creation</h3>
 * The generalized version only has one method to create a single private key,
 * due to its limited use.  It randomly generates the distinct primes <i>p, q</i>
 * and also generates the master key <i>d</i> to return a private key.
 * 
 * The public key is retrievable by calling
 * {@link paillierp.key.PaillierKey#getPublicKey() getPublicKey()} from the
 * returned key.
 * 
 * <h3>Paillier Threshold Key Creation</h3>
 * There are three methods to create the Paillier threshold keys.  Each method
 * requires the <i>l</i> and <i>w</i> parameters, indicating that <i>l</i>
 * private keys will be produced such that any <i>w</i>&ge;<i>l</i>/2 can
 * decrypt ciphertexts encrypted with the public key.
 * <p>
 * The methods are either given or randomly generate four distinct primes:
 * <i>p</i> and <i>q</i> of the same length <i>s</i>, and
 * <i>p</i><sub>1</sub> and <i>q</i><sub>1</sub> of length <i>s</i>-1.
 * <i>p</i> and <i>q</i> must be strong primes where
 * <i>p</i>=2<i>p</i><sub>1</sub>+1 and <i>q</i>=2<i>q</i><sub>1</sub>+1.
 * The public key is then <i>pq</i>=<i>n</i>
 * <p>
 * The method then either is given or randomly generates
 *  the master private key, <i>d</i> which can decrypt any message encrypted
 *  with the above <i>n</i>.  It chooses (is given) <i>d</i> where <i>d</i>=0
 * mod <i>p</i><sub>1</sub><i>q</i><sub>1</sub> and <i>d</i>=1 mod <i>pq</i>.
 * The method constructs a (<i>w</i>-1)-degree polynomial
 * <i>f</i>(<i>x</i>) with all random coefficients and fixes the last coefficient
 * (<i>a</i><sub>0</sub>) at <i>d</i>.  From <i>f</i> do we
 * construct the <i>l</i> private keys and the public verification keys
 * (used to verify correct share decryption).
 * <p>
 * The public key is retrievable by calling
 * {@link paillierp.key.PaillierThresholdKey#getThresholdKey()
 * getThresholdKey()} or {@link paillierp.key.PaillierKey#getPublicKey()
 * getPublicKey()} from any of the returned keys.
 * <p>
 *   Note that due to the
 * construction of this system, all the threshold keys must be created
 * simultaneously; after <i>l</i> keys are created, no more can be generated
 * without redistributing the private keys again.  <i>l</i> cannot change as
 * the value &Delta; used in the distributed verification keys remains the same,
 * and <i>w</i> cannot change because it is used in the one-time-use function
 * <i>f</i> which is again used in the distributed verification keys.
 * <p>
 * Given the nature of the threshold version of the scheme, an array of private
 * keys is passed around and returned by this class.  For this reason, it is
 * assumed only for the key distributor.  After creating an array of private
 * keys (one for each decryption servers), it is expected that the key
 * distributor will distribute the private keys and then destroy all evidence;
 * a collection of any <code>w</code> private keys can create a master private
 * key, capable of single handedly decrypting any ciphertext, loosing all
 * thresholding features.
 * 
 * <h3>Other methods</h3>
 * There are other provided methods to write out the Paillier threshold keys
 * to a file for primarily private, testing use only.
 * 
 * @author Murat Kantarcioglu
 * @author Sean Hall
 * @author James Garrity
 */
public class KeyGen {
   
	/**
	 * This function return the keys for the Paillier class
	 * given the number of bits required for the construction.
	 * <p>
	 * This function randomly generates two primes <i>p, q</i> of length
	 * <code>s</code>, and creates the key (<code>n</code>, <code>d</code>)
	 * where <code>n</code>=<i>pq</i> and <code>d</code>=lcm(<i>p,q</i>), as
	 * in Paillier's original scheme.
	 * 
	 * @param s     Specifies the number of bits required for the prime factor 
	 *              of n.
	 * @param seed  Specifies the seed for the random number generator used.  
	 * @return      Private key for the generalized Paillier cryptosystem
	 */
	public static PaillierPrivateKey PaillierKey(int s, long seed) {
	/* TODO Should this method be incorporated into PaillierKey as another
	 * constructor? */
		if (s<=0) {
			throw new IllegalArgumentException("Number of bits set is less than 0");
		}
		
		BigInteger minprm=null;
		BigInteger maxprm=null;
		BigInteger phin=null;
		BigInteger p;
		BigInteger q;
		BigInteger d;
		BigInteger n;
		SecureRandom rnd;
		boolean ok=false;
		
		//Initialize the random number generator
		rnd= new SecureRandom(BigInteger.valueOf(seed).toByteArray());
		
		do {
			p = KeyGen.getPrime(s, rnd);
			q = KeyGen.getPrime(s, rnd); 
			minprm = q.min(p);
			maxprm = q.max(p);
			//Make the smallest prime p, maximum q
			p = minprm;
			q = maxprm;
			// Now verify that  p-1 does not divide q
			if((q.mod(p.subtract(BigInteger.ONE))).compareTo(BigInteger.ZERO)!=0) {
				ok=true;
			}
		} while(!ok);
		
		//n=p*q
		n=p.multiply(q);
		  		  
		//phi(n)=(p-1)*(q-1);
		phin=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		  
		//Now we can calculate the Carmichael's function for n
		//i.e., lcm(p-1,q-1)
		//Note that phi(n)=gcd(p-1,q-1)*lcm(p-1,q-1)
		d=phin.divide((p.subtract(BigInteger.ONE)).gcd(q.subtract(BigInteger.ONE)));
		
		return new PaillierPrivateKey(n, d, seed);
	}

	/**
	 * This function generates keys for the Paillier Threshold version.  This
	 * function randomly generates the four distinct primes <i>p</i>,
	 * <i>q</i>, <i>p</i><sub>1</sub>, and
	 * <i>q</i><sub>1</sub>, and chooses the master private key <i>d</i> to
	 * construct {@code l} partial keys where any {@code w} of them can
	 * correctly decode a ciphertext.
	 * 
	 * @param s    Specifies the number of bits required for the prime factor 
	 *             of n.
	 * @param l    Number of decryption servers.
	 * @param w    Threshold number of decryption servers.  Must be
	 *             &le;&frac12;<code>l</code>
	 * @param seed Specifies the seed for the random number generator used.  
	 * @return     An array of <code>l</code> private threshold keys.
	 * @see        KeyGen
	 */
	public static PaillierPrivateThresholdKey[]
	                        PaillierThresholdKey(int s, int l, int w, long seed)
	{
		if (s<=0) {
			throw new IllegalArgumentException("Number of bits set is less than 0");
		}
		//Both p1 and q1 is prime size s-1;
		BigInteger p1=null;
		BigInteger q1=null;
		
		//p is prime and p=2*p1+1
		BigInteger p=null;
		
		//q is prime and q=2*q1+1
		BigInteger q=null;
	   
		//m will be set to p1*q1
		BigInteger m=null;
	   
		//n=p*q
		BigInteger n=null;
	   
		//n*n
		BigInteger nSquare=null;
	   
		//n*m
		BigInteger nm=null;
	   
		//v is the generator of $Z^*_{ }$
		BigInteger v=null;
	   
		//d=1 mod n and d=0 mod m
		BigInteger d=null;
	   
		//Initialize the random number generator
		SecureRandom rnd= new SecureRandom(BigInteger.valueOf(seed).toByteArray());

		//First we need to generate p1,q1,p,q all are prime
		//p1 and q1 are s-1 bit long 
		//p=2*p1+1, q=2*q1+1
		System.out.println("Generating p and p1");
		BigInteger[] primes=KeyGen.genSafePrimes(s,rnd);
		p1=primes[0];
		p=primes[1];
		System.out.println("Generating q and q1");
		do {
			primes=KeyGen.genSafePrimes(s,rnd);
			q1=primes[0];
			q =primes[1];
		} while(p.equals(q)||p.equals(q1)||q.equals(p1));

		//Note n= p*q
		n=p.multiply(q);

		//Note m=p1*q1
		m=p1.multiply(q1);

		//Note nm=n*m
		nm=n.multiply(m);

		//nSquare=n*n
		nSquare=n.multiply(n);

		// next d need to be chosen such that
		// d=0 mod m and d=1 mod n, using Chinese remainder thm
		// we can find d using Chinese remainder thm
		// note that $d=(m. (m^-1 mod n))$
		System.out.println("Generating d");
		d=m.multiply(m.modInverse(n));

		//a[0] is equal to d
		//a[i] is the random number used for generating the polynomial
		//between 0... n*m-1, for 0 < i < w 
		BigInteger[] a = new BigInteger[w];
		a[0] = d;
		for(int i = 1; i < w; i++) {
			do {
				a[i] = new BigInteger(nm.bitLength(), rnd);
				//a[i] = d;
			} while(a[i].compareTo(nm) > 0);
		}

		//We need to generate v
		//Although v needs to be the generator of the squares in Z^*_{n^2}
		//I will use a heuristic which gives a generator with high prob.
		//get a random element r such that gcd(r,nSquare) is one
		//set v=r*r mod nSquare. This heuristic is used in the Victor Shoup
		//threshold signature paper.
		BigInteger r=null;
		boolean ok=false;
		System.out.println("Generating v");
		do
		{
			//generate r such that gcd(r,n)=1
			r=new BigInteger(4*s,rnd);  
			if(((BigInteger.ONE).compareTo(r.gcd(n)))==0)
				ok=true;
		}while(ok==false);
		// we can now set v to r*r mod nSquare
		v=(r.multiply(r)).mod(nSquare);

		System.out.println("p :" + p.toString());
		System.out.println("p1:" + p1.toString());
		System.out.println("q :" + q.toString());
		System.out.println("q1:" + q1.toString());
		System.out.println("d :" + d.toString());
		System.out.println("v :" + v.toString());

		//This array holds the resulting keys
		BigInteger[] shares = new BigInteger[l];
		BigInteger[] viarray = new BigInteger[l];

		//delta = l!
		BigInteger delta = KeyGen.factorial(l);
		BigInteger combineSharesConstant = BigInteger.valueOf(4).multiply(delta.multiply(delta)).modInverse(n);

		for(int index = 0; index < l; index++) {
			shares[index] = BigInteger.ZERO;
			int X = index + 1;
			for(int i = 0; i < w; i++) {
				shares[index] = shares[index].add(a[i].multiply(BigInteger.valueOf((long)Math.pow(X, i))));
			}
			shares[index] = shares[index].mod(nm);

			viarray[index] = v.modPow(shares[index].multiply(delta), nSquare);
		}

		PaillierPrivateThresholdKey[] res = new PaillierPrivateThresholdKey[l];
		for(int i = 0; i < l; i++) {
			res[i] = new PaillierPrivateThresholdKey(n, l, combineSharesConstant, w, v, 
					viarray, shares[i], i+1, rnd.nextLong());
		}

		/*System.out.print("The polynomial f(X)=");
		for (int i = a.length-1; i > 0; i--) {
			System.out.print(a[i]+"X^"+i+" + ");
		}
		System.out.println(a[0]);*/
		
		return res;
	}
	
	/**
	 * This function generates keys for the Paillier Threshold version.
	 * <p>
	 * This function accepts the four distinct primes and the integer {@code d}
	 * to create {@code l} private keys.
	 * 
	 * @param p1   Prime number
	 * @param q1   Prime number, different from {@code p1}
	 * @param p    Prime number, equal to {@code 2*p1+1}
	 * @param q    Prime number, equal to {@code 2*q1+1}
	 * @param d    Master private key
	 * @param v    Verification key
	 * @param l    Number of decryption servers.
	 * @param w    Threshold number of decryption servers.  Must be
	 *             &le;&frac12;<code>l</code>
	 * @param seed Specifies the seed for the random number generator used.  
	 * @return     An array of <code>l</code> private threshold keys.
	 * @see        KeyGen
	 */
	public static PaillierPrivateThresholdKey[] PaillierThresholdKey(BigInteger p1, BigInteger q1, BigInteger p, BigInteger q, 
			BigInteger d, BigInteger v, int l, int w, long seed)
	{
		
		//m will be set to p1*q1
		BigInteger m=null;

		//n=p*q
		BigInteger n=null;

		//n*n
		BigInteger nSquare=null;

		//n*m
		BigInteger nm=null;

		//Initialize the random number generator
		SecureRandom rnd= new SecureRandom(BigInteger.valueOf(seed).toByteArray());

		//Note n= p*q
		n=p.multiply(q);

		//Note m=p1*q1
		m=p1.multiply(q1);

		//Note nm=n*m
		nm=n.multiply(m);

		//nSquare=n*n
		nSquare=n.multiply(n);

		//a[0] is equal to d
		//a[i] is the random number used for generating the polynomial
		//between 0... n*m-1, for 0 < i < w 
		BigInteger[] a = new BigInteger[w];
		a[0] = d;
		for(int i = 1; i < w; i++) {
			do {
				a[i] = new BigInteger(nm.bitLength(), rnd);
			} while(a[i].compareTo(nm) > 0);
		}

		//This array holds the resulting keys
		BigInteger[] shares = new BigInteger[l];
		BigInteger[] viarray = new BigInteger[l];

		//delta = l!
		BigInteger delta = KeyGen.factorial(l);
		BigInteger combineSharesConstant = BigInteger.valueOf(4).multiply(delta.multiply(delta)).modInverse(n);

		for(int index = 0; index < l; index++) {
			shares[index] = BigInteger.ZERO;
			int X = index + 1;
			for(int i = 0; i < w; i++) {
				shares[index] = shares[index].add(a[i].multiply(BigInteger.valueOf((long)Math.pow(X, i))));
			}
			shares[index] = shares[index].mod(nm);

			viarray[index] = v.modPow(shares[index].multiply(delta), nSquare);
		}

		PaillierPrivateThresholdKey[] res = new PaillierPrivateThresholdKey[l];
		for(int i = 0; i < l; i++) {
			res[i] = new PaillierPrivateThresholdKey(n, l, combineSharesConstant, w, v, 
					viarray, shares[i], i+1, rnd.nextLong());
		}

		System.out.print("The polynomial f(X)=");
		for (int i = a.length-1; i > 0; i--) {
			System.out.print(a[i]+"X^"+i+" + ");
		}
		System.out.println(a[0]);

		return res;

	}
	
	/**
	 * This function generates keys for the Paillier Threshold version
	 * and stores them in a file.
	 * 
	 * @param fname   String of the file name where the private keys will be
	 *                stored
	 * @param s       Specifies the number of bits required for the prime factor 
	 *                of n.
	 * @param l       Number of decryption servers.
	 * @param w       Threshold number of decryption servers.  Must be
	 *                &le;&frac12;<code>l</code>
	 * @param seed    Specifies the seed for the random number generator used.
	 */
	public static void PaillierThresholdKey(String fname, int s, int l, int w, long seed) throws IOException
	{
		PaillierPrivateThresholdKey[] keys = KeyGen.PaillierThresholdKey(s, l, w, seed);

		FileWriter File= new FileWriter(fname);
		PrintWriter out=new PrintWriter(File);
		out.println("l:" + l);
		out.println("w:" + w);
		out.println("v:" + keys[0].getV());
		out.println("n:" + keys[0].getN());
		out.println("combineSharesConstant:" + keys[0].getCombineSharesConstant());
		for(int i = 0; i < keys.length; i++) {
			out.println("s" + i + ":" + keys[i].getSi().toString());
			out.println("v" + i + ":" + keys[i].getVi()[i].toString());
		}
		out.close();
	}
	
	/**
	 * This function loads keys for the Paillier Threshold version
	 * from a file.
	 * <p>
	 * The public values and public key are retrievable by calling
	 * {@link paillierp.key.PaillierThresholdKey#getThresholdKey()
	 * getThresholdKey()} or {@link paillierp.key.PaillierKey#getPublicKey()
	 * getPublicKey()}, respectively, from any of the returned keys.
	 * 
	 * @param fname    String of the file name where the private keys are
	 *                 stored
	 * @return         An array of preconstructed private keys
	 */
	public static PaillierPrivateThresholdKey[] PaillierThresholdKeyLoad(String fname)
	{
		int l, w;
		BigInteger v, n, combineSharesConstant;
		BigInteger[] shares, viarray;
		PaillierPrivateThresholdKey[] res = null;
		try {  
			FileReader File= new FileReader(fname);
			BufferedReader buf=new BufferedReader(File);
			String line=buf.readLine();
			l = Integer.parseInt(line.split(":")[1]);
			
			line = buf.readLine();
			w = Integer.parseInt(line.split(":")[1]);
			
			line = buf.readLine();
			v = new BigInteger(line.split(":")[1]);
			
			line = buf.readLine();
			n = new BigInteger(line.split(":")[1]);
			
			line = buf.readLine();
			combineSharesConstant = new BigInteger(line.split(":")[1]);
			
			shares = new BigInteger[l];
			viarray = new BigInteger[l];
			
			for(int i = 0; i < l; i++) {
				line = buf.readLine();
				shares[i] = new BigInteger(line.split(":")[1]);
				line = buf.readLine();
				viarray[i] = new BigInteger(line.split(":")[1]);
			}
			
			res = new PaillierPrivateThresholdKey[l];
			SecureRandom rnd = new SecureRandom();
			for(int i = 0; i < l; i++) {
				res[i] = new PaillierPrivateThresholdKey(n, l, combineSharesConstant, w, v, 
						viarray, shares[i], i+1, rnd.nextLong());
			}
			
			buf.close();

		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
		return res;
	}
	
//	/**
//	 * This function generates 5 primes for the Paillier Threshold version
//	 * and stores them in a file.
//	 * 
//	 * @param fname   String of the file name where the private keys will be
//	 *                stored
//	 * @param s       Specifies the number of bits required for the prime factor 
//	 *                of n.
//	 * @param seed    Specifies the seed for the random number generator used.
//	 */
//	public static void PrimeList(String fname, int s, long seed) throws IOException
//	{
//		FileWriter File= new FileWriter(fname);
//		PrintWriter out=new PrintWriter(File);
//		
//		BigInteger[] p;
//		
//		SecureRandom rnd = new SecureRandom();
//		
//		out.println(s);
//		
//		List<BigInteger> li = new ArrayList<BigInteger>();
//		
//		for (int i = 0; i < 5; i++) {
//		do{
//			p = genSafePrimes(s,rnd);
//		} while (li.contains(p[0]));
//		
//		out.println(i+":  "+p[0]);
//		out.println(i+"': "+p[1]);
//		}
//		out.close();
//	}
	
	/**
	 * Returns a BigInteger that is probably a prime number of length
	 * {@code length}.
	 * 
	 * @param length  length of prime number
	 * @param random  Random number generator
	 * @return        BigInteger that is probably a prime
	 * @see           java.math.BigInteger#probablePrime(int,Random)
	 */
	public static BigInteger getPrime(int length, Random random) {
		return BigInteger.probablePrime(length, random);
	}

	/**
	 * This function returns 2 safe primes <i>p</i> (<code>s</code> bits long)
	 * and <i>p</i><sub>1</sub> (<code>s</code>-1 bits long)
	 * such that <i>p</i>=2<i>p</i><sub>1</sub>+1.
	 * <p>
	 * This function implements Algorithm 4.86 of <i>Handbook of
	 * Applied Cryptography</i>
	 * 
	 * @param s     Specifies the number of bits required for the prime
	 *              factor p and q 
	 * @param rnd   Random number generator.  
	 * @return      returns a BigInteger array where 
	 *              BigInteger[0] is <i>p</i><sub>1</sub>,
	 *              BigInteger[1] is <i>p</i>
	 * 
	 */
	private static BigInteger[] genSafePrimes(int s, Random rnd)
	{
		BigInteger p1=null;
		BigInteger p=null;
		BigInteger[] res= new BigInteger[2];
		boolean ok=false;
		System.out.println("Trying prime");
		do 
		{    

			p1=BigInteger.probablePrime(s-1,rnd);
			p=(p1.shiftLeft(1)).add(BigInteger.ONE);
			if(p.isProbablePrime(50))
				ok=true;
			//else
				//	  System.out.println("Unsuccessful try");
		}while(ok==false);
		System.out.println("Finally a good pair");
		res[0]=p1;
		res[1]=p;
		return res;
	}

	/**
	 * Computes the factorial of {@code n}.
	 * @param n     the integer
	 * @return      {@code n}! = <code>n</code>(<code>n</code>-1)(<code>n</code>
	 *              -2)(<code>n</code>-3)...(2)(1).
	 */
	public static BigInteger factorial(int n) {
		BigInteger res = BigInteger.ONE;
		for(int i = n; i > 1; i--) {
			res = res.multiply(BigInteger.valueOf(i));
		}
		return res;
	}

}
