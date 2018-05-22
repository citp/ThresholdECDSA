package l2fheBased.thresholdDSA.sign;

import ACNS.ZeroKnowledgeProofs.PublicParameters;
import Common.Commitments.MultiTrapdoorCommitment;
import Common.Commitments.MultiTrapdoorMasterPublicKey;
import l2fheBased.thresholdDSA.data.*;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;
import paillierp.key.KeyGen;
import paillierp.key.PaillierKey;
import paillierp.key.PaillierPrivateThresholdKey;
import paillierp.l2fhe.L2FHE;

import java.math.BigInteger;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

public class Test {
    public static void main(String[] args) {

        Random random = new Random();

        PaillierPrivateThresholdKey[] privatePaillierKeyShares = KeyGen.PaillierThresholdKey(
                256, // number of bits for prime factor n
                10, // number of decryption servers
                4, // threshold
                new Random().nextLong()
        );

        PaillierKey paillierKey = privatePaillierKeyShares[0].getPublicKey();

        /*
          - nTilde which is auxiliary RSA modulus which is a product of two safe primes
          - h1, h2 used to construct range commitments for ZKRP(*)

          (*)Zero-Knowledge Range Proofs (ZKRP) allow for proofing that a number lies within a certain range.
            ZKRP is the underlying encryption scheme being used is Paillier’s scheme.
        */
        BigInteger pTilde = KeyGen.getPrime(128, random);
        BigInteger qTilde = KeyGen.getPrime(128, random);
        BigInteger nTilde = pTilde.multiply(qTilde);

        BigInteger h1 = new BigInteger("1000");
        BigInteger h2 = qTilde.add(new BigInteger("1000"));


        MultiTrapdoorMasterPublicKey multiTrapdoorMasterPublicKey = MultiTrapdoorCommitment.generateNMMasterPublicKey();

        /*
          Kindly borrowed from http://www.bouncycastle.org/wiki/display/JA1/Elliptic+Curve+Key+Pair+Generation+and+Key+Factories#EllipticCurveKeyPairGenerationandKeyFactories-FromExplicitParameters.1
         */
        ECCurve curve = new ECCurve.F2m(
                239, // m
                36, // k
                new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
                new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16)); // b
        ECParameterSpec params = new ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
                new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783"), // n
                BigInteger.valueOf(4)); // h
        ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(
                new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), // d
                params);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(
                curve.decodePoint(Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), // Q
                params);

        ECDomainParameters ecDomainParameters = new ECDomainParameters(
                params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()
        );
        PublicParameters publicParameters = new PublicParameters(ecDomainParameters, nTilde, h1, h2, paillierKey);

        List<PlayerSigner> players = new ArrayList<>();

        byte[] message = "Hello Universe".getBytes();

        for (int i = 0; i < 10; i++) {
          players.add(new PlayerSigner(
             publicParameters,
             multiTrapdoorMasterPublicKey,
             privatePaillierKeyShares[i],
             new L2FHE(privatePaillierKeyShares[i]).encrypt1(priKeySpec.getD()),
             message
          ));
        }

        Round1Message[] round1Messages = players.stream().map(p -> p.round1()).toArray(Round1Message[]::new);
        Round2Message[] round2Messages = players.stream().map(p -> p.round2(round1Messages)).toArray(Round2Message[]::new);
        Round3Message[] round3Messages = players.stream().map(p -> p.round3(round2Messages)).toArray(Round3Message[]::new);
        Round4Message[] round4Messages = players.stream().map(p -> p.round4(round3Messages)).toArray(Round4Message[]::new);
        List<DSASignature> signatures = players.stream().map(p -> p.outputSignature(round4Messages)).collect(Collectors.toList());

        for (DSASignature signature: signatures) {
            System.out.println("r=" + signature.r + ", s=" + signature.s);
        }
    }
}
