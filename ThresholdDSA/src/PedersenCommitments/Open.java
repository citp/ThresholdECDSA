package PedersenCommitments;

public class Open<T> {
	
	private final T secret;
	private final T randomness;
	
	public Open(T secret, T randomness) {
		this.secret = secret;
		this.randomness = randomness;
	}

	public T getSecret() {
		return secret;
	}
	
	public T getRandomness() {
		return randomness;
	}

}
