# Writeup for schnore by enigcryptist

## Details

- **Author**: enigcryptist
- **Type**: crypto
- **Difficulty**: Easy
- **Flag format**: `bctf{...}`

## Run Instructions

```
# Build Docker image
./run.sh
# Run chal in a Docker container
docker run -it deploy_schnore
# In a new terminal...
nc localhost 5093
```

## Solution

### Background: Schnorr Signatures and Fiat-Shamir ZKPs
This is a (relatively) simple attack against weak Fiat-Shamir (FS) transformations of interactive into non-interactive zero-knowledge proofs of knowledge.

First, the public parameters are decided as primes $p,q$ and an element $g$ which produces an order $q$ multiplicative group $\mathbb{G}$. A signer decides on a private signing key $x$ and its corresponding public verification key $X = g^x \mod p \in \mathbb{Z}_p^*$. The initial construction roughly follows what's called a "Sigma protocol", named as such due to the shape of the protocol interaction resembling $\Sigma$ [1]:
1. (-) The Prover and Verifier first send over any relevant **public information** shared between the Prover and Verifier (here, $p,q,g$. Ideally also $X$; see below).
2. (\\) The Prover then generates a random value (here, $a \gets \mathbb{Z}_p^*$) and sends its corresponding **commitment** to the Verifier (here, $A = g^a \bmod p \in \mathbb{G}$).
3. (/) The Verifier responds back with a **challenge** value (here, $c \in \mathbb{Z}_p^*$), attempting to verify the Prover's knowledge of some secret **witness** (here, $x$) corresponding with the public key (here, $X := g^x \mod p \in \mathbb{G}$). 
4. (-) The Prover computes the final **proof** based on both the commitment and the challenge (here, $z = a + c * x \mod p \in \mathbb{Z}_p^*$, which is checked by the Verifier using the corresponding public keys and other information.

At a high level, the Fiat-Shamir (FS) heuristic provides a mechanism for transforming *interactive* Sigma proofs such as these into *non-interactive* Sigma proofs by instead having the Prover hash these public values and commitments as its challenge instead of having it sent by the Verifier. As long as the hash ooutput is cryptographically "random-looking" (more formally, that the hash function $H$ can be assumed to be a random oracle which cannot be inverted or guessed prior to querying its output), this works effectively the same way an interactive challenge would. FS can be classified into two types
1. **weak Fiat-Shamir**, where only the necessary committed values are hashed into a challenge,
2. **strong Fiat-Shamir**, where it is hashed together with ALL other public information that is used by the protocol and known to both the prover and verifier in advance (group generator(s), group description, public key(s), etc.).

As we shall soon see, not expecting enough information in the hash as a challenge makes it easy for the prover to lie for them to about knowledge of the secret signing key $x$ in the non-interactive setting.

This challenge involves a cryptographic proof over a Schnorr signatures, which is based on the discrete log hardness assumption. In a normal but weak FS Schnorr protocol, an honest Prover would generate $a \gets \mathbb{F}_p$ randomly and compute $A = g^a \mod p$ as its commitment, with $c = H(g,p,A)$ as its challenge. As its proof of knowledge on $x$, it computes $z = a + c * x \mod p$ before sending $(A,z)$ to the Verifier. The Verifier then checks this was correctly computed by computing $c = H(g,p,A)$ themselves and checking the following:
$$g^z ?= A * X^c \mod p$$

### Weak Fiat-Shamir Vulnerability

In many situations, where the public key is decided ahead of time by the prover and verifier, this is sufficient to ensure that even a malicious prover must know $x$ corresponding with $X = g^x$, and is bound to the public information chosen to be included in the hash. *However*, if the malicious prover is adaptive and has the ability to control which public key $X$ is used the verifier (i.e., is not bound to to commit to $X = g^x$*before* computing and sending over $z = a + c * x$), this is insufficient to stop the prover from lying about knowing $x$.

Instead, consider a malicious prover who does not know $x$. Since they can't compute discrete log of $X = g^x$ to get $x$, they're forced to choose $z \gets \mathbb{F}_p^*$ randomly instead of compute it, and decides to choose $A \gets \mathbb{G}$ randomly as well, then computes $c = H(g,p,A)$ as expected. To ensure that the verification check passes, the malicious prover simply re-arrange the verification equation to solve for $X$, and has the verifier agree to use this public key $X$:
$$X = (A^{-1} * g^z)^{(c^{-1} \mod p-1)} \mod p$$

And so, as long as the attacker can convince the verifier to use a maliciously chosen verification key $X$ *after* having generated $A$ and $z$, and that this value $X$ is not included within the challenge itself (i.e. as in strong FS), they have successfully forged a satisfying proof of knowledge on $x$ to the Verifier while only having known $X$. The attack involves following these steps above to obtain the flag.

The only caveat is that $c = H(g,p,A)$ might not always be invertible in the exponent (i.e. modulo $\phi(p) = p - 1$) since $p-1$ is even and might share a common factor (here, we made it simple for you by ensuring $gcd(c, p-1) = 2)$. With this specific challenge value $c$, you might have to do a bit more algebra to recover $X$ by finding a variant ($c^{-1'}$) which is computable with gcd 1, computing $X^2 \mod p$, then finding $X$ via a quadratic residue ("modular square root") algorithm such as Tonelli-Shanks. But this is a relatively easy-level trick used to recover messages from poorly chosen RSA keys, so I won't go into too much more detail here :)

See `solve.py` and below for more detail, courtesy [2,3]:

![A comparison between "Interactive Schnorr protocol", "Strong/Weak Fiat-Shamir transformation", and "Attack against weak Fiat-Shamir" protocols described above. The picture is captioned with "Fig. 1: Example weak Fiat-Shamir attack against Schnorr proofs for relation $\{((\mathbb{G},g),X; x) | X = g^x\}$".](./schnore/wFS-Schnorr-attack.png)

### References and Further Reading

[1] https://www.zkdocs.com/docs/zkdocs/protocol-primitives/fiat-shamir/
[2] Q. Dao, J. Miller, O. Wright and P. Grubbs, "Weak Fiat-Shamir Attacks on Modern Proof Systems," 2023 IEEE Symposium on Security and Privacy (SP), San Francisco, CA, USA, 2023, pp. 199-216, doi: 10.1109/SP46215.2023.10179408.
[3] Bernhard, D., Pereira, O., Warinschi, B. (2012). How Not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios. In: Wang, X., Sako, K. (eds) Advances in Cryptology – ASIACRYPT 2012. https://doi.org/10.1007/978-3-642-34961-4_38

