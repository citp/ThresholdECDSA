package thresholdDSA.data;

import java.math.BigInteger;

import PedersenCommitments.Open;
import ZeroKnowledgeProofs.Zkp_i1;

public class Round2Message {

	public final Open<BigInteger> openUi;
	public final Open<BigInteger> openVi;
	public final Zkp_i1 zkp1;

	public Round2Message(Open<BigInteger> openUi, Open<BigInteger> openVi,
			Zkp_i1 zkp1) {
		this.openUi = openUi;
		this.openVi = openVi;
		this.zkp1 = zkp1;
	}

}
