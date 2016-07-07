package ACNS.thresholdDSA.data;

import java.math.BigInteger;

import ACNS.ZeroKnowledgeProofs.Zkp_i1;
import Common.Commitments.Open;

public class Round2Message {

	public final Open<BigInteger> openUiVi;
	public final Zkp_i1 zkp1;

	public Round2Message(Open<BigInteger> openUiVi, Zkp_i1 zkp1) {
		this.openUiVi = openUiVi;
		this.zkp1 = zkp1;
	}

}
