package Common.Commitments;

import java.io.Serializable;

public class PedersenPublicParams<T> implements Serializable {
	
	private static final long serialVersionUID = 8372645283516642704L;
	
	public final T order;
	public final T modulus;
	public final T g;
	public final T h;
	
	public PedersenPublicParams(T order, T modulus, T g, T h) {
		this.order = order;
		this.modulus = modulus;
		this.g = g;
	    this.h = h;
	}

}
