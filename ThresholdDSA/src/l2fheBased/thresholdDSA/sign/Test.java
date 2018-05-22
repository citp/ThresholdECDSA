package l2fheBased.thresholdDSA.sign;

import ACNS.ZeroKnowledgeProofs.PublicParameters;
import Common.Commitments.MultiTrapdoorCommitment;
import Common.Commitments.MultiTrapdoorMasterPublicKey;
import l2fheBased.thresholdDSA.data.*;
import paillierp.key.KeyGen;
import paillierp.key.PaillierKey;
import paillierp.key.PaillierPrivateThresholdKey;

import java.math.BigInteger;
import java.util.Random;

public class Test {
    public static void main(String[] args) {
        System.out.println(
          "Curve Params\n" +
          "q = " + BitcoinParams.q + "\n" +
          "G.x = " + BitcoinParams.G.getX().toBigInteger() + "\n" +
          "G.y = " + BitcoinParams.G.getY().toBigInteger() + "\n" +
          "N = " + BitcoinParams.CURVE.getN()
        );

        /*
          Generate Paillier keyChoose

          P and Q are two large prime numbers chosen randomly and independently of each other such that
          gcd(pq, (p-1)(q-1)) = 1


          https://en.wikipedia.org/wiki/Paillier_cryptosystem
          https://crypto.stackexchange.com/q/19056/59088
          https://crypto.stackexchange.com/q/18058/59088
         */
        BigInteger p = new BigInteger("179426129");
        BigInteger q = new BigInteger("179426549");
        PaillierKey paillierKey = new PaillierKey(p, q, new Random().nextLong());

        /*
          PublicParameters holds the following values:
          - elliptic curve base point G, a generator of the elliptic curve with large prime order n
          - nTilde which is auxiliary RSA modulus which is a product of two safe primes
          - h1, h2 used to construct range commitments for ZKRP(*)
          - Paillier public key

          (*)Zero-Knowledge Range Proofs (ZKRP) allow for proofing that a number lies within a certain range.
        */

        BigInteger pTilde = new BigInteger("15487237");
        BigInteger qTilde = new BigInteger("15486227");
        BigInteger nTilde = pTilde.multiply(qTilde);

        BigInteger h1 = new BigInteger("1241414124124");
        BigInteger h2 = new BigInteger("1241414125124");

        PublicParameters publicParameters = new PublicParameters(BitcoinParams.CURVE, nTilde, h1, h2, paillierKey);

        MultiTrapdoorMasterPublicKey multiTrapdoorMasterPublicKey = MultiTrapdoorCommitment.generateNMMasterPublicKey();

        PaillierPrivateThresholdKey[] keys = KeyGen.PaillierThresholdKey(
                64, // number of bits for prime factor n
                10, // number of decryption servers
                4, // threshold
                new Random().nextLong()
        );



    }
}
