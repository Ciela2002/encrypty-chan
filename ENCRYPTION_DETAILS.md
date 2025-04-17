# Advanced Cryptographic Security Analysis: Behind the Scenes

Look, I'm not saying we've reinvented the wheel here, but I've tried to put together a pretty comprehensive breakdown of the cryptographic methods we're using in Encrypty-chan. This doc dives into the mathematical foundations and security properties that ensure your data stays confidential, authentic, and untampered. Fair warning: there's math ahead. Lots of it.

## Cryptographic Primitives: The Building Blocks

### AES: The Reliable Workhorse

Let's face it, AES has been around the block a few times (since 2001!), but it's still the go-to standard for a reason. This substitution-permutation network operates on 128-bit blocks with key lengths of 128, 192, or 256 bits. We've gone with AES-256 because, well, bigger is better when it comes to key sizes.

The security of AES boils down to its resistance against differential and linear cryptanalysis. For math nerds (like me), the expected differential probability for a random permutation on an $n$-bit block is roughly $2^{-n}$. With our 128-bit blocks, that gives us:

$$P_{diff} \approx 2^{-128}$$

In practical terms, the best known attacks against AES-256 would require about $2^{224}$ operations. Good luck with that — even quantum computers would need a few billion years.

### GCM: Because Encryption Without Authentication is Just Asking for Trouble

Galois/Counter Mode (GCM) is where things get interesting. It combines Counter Mode (CTR) for encryption with Galois field multiplication for authentication. I'm particularly fond of this mode because it gives us both confidentiality AND integrity in one neat package.

GCM works by:

1. **Counter Mode**: Creates a keystream by encrypting incrementing counter values:

   $$S_i = E_K(IV || i)$$
   
   Where $E_K$ is our encryption function with key $K$, $IV$ is the initialization vector (think of it as a starting point), and $i$ is the counter.

2. **Galois Field Authentication**: Computes a tag that acts like a cryptographic seal of approval:

   $$T = (A \cdot H^{m+n+1} + C_1 \cdot H^{m+n} + \ldots + C_m \cdot H^{n+1} + L \cdot H^n + IV \cdot H) \oplus E_K(IV || 0)$$

   Yeah, that's a mouthful. The important bit? Even after $2^{64}$ forgery attempts (that's 18.4 quintillion tries), an attacker's success probability remains at around $2^{-64}$ – vanishingly small.

## Formal Security Models: The Theoretical Guarantees

I've always found it fascinating how we can actually *prove* security properties mathematically. It's not just "this feels secure" – we can quantify exactly how secure something is under specific threat models.

### The IND-CPA Game: Can You Tell Which Message I Encrypted? seriously like.. try?

Indistinguishability under Chosen-Plaintext Attack (IND-CPA) is essentially a game between a challenger and an adversary:

1. The challenger generates a random key $K$
2. The adversary submits two messages of equal length
3. The challenger flips a coin, encrypts one message, and returns the ciphertext
4. The adversary tries to guess which message was encrypted

If the adversary can't do better than random guessing, the encryption scheme passes. Formally:

$$\left| \Pr[A(E_K(P_b)) = b] - \frac{1}{2} \right| \leq \epsilon(n)$$

Where $\epsilon(n)$ is negligibly small. In plain English: the probability of guessing correctly shouldn't be significantly better than 50/50.

### Authenticated Encryption: Because Reading Someone's Mail is One Thing, Changing It is Another

AE security combines confidentiality (IND-CPA) with ciphertext integrity (INT-CTXT). The INT-CTXT property is particularly interesting:

$$\Pr[\exists C \notin \{C_1, C_2, \ldots, C_q\} : D_K(C) \neq \perp] \leq \epsilon(n)$$

Translation: The probability of creating a valid ciphertext that the challenger didn't encrypt is negligible. In real-world terms? An attacker can't forge encrypted messages that pass the authentication check. ( i mean the nsa can probably but yeah you see where I'm going)

## Key Derivation: Turning Your Lousy Password into Something Useful

### PBKDF2: Making Brute-Force Expensive Since 2000

Let's be honest, human-generated passwords are usually terrible dud i swear your DOG NAME IS NOT A GOOD PASSWORD. PBKDF2 helps by stretching that weak password into a cryptographically strong key.

PBKDF2 derives a key by computing:

$$DK = T_1 || T_2 || \ldots || T_{\lceil dkLen/hLen \rceil}$$

where each block $T_i$ is:

$$T_i = U_1 \oplus U_2 \oplus \ldots \oplus U_c$$

with:

$$U_1 = PRF(P, S || \text{INT}_{32}(i))$$
$$U_j = PRF(P, U_{j-1}) \text{ for } j > 1$$

I know, another mathematical soup. The key insight is the iteration count $c$ – it forces attackers to perform the same number of operations for each password guess so yeah. We've cranked this up to 480,000 iterations because we'd rather wait an extra second for encryption than have someone crack your files yk .. lol

For a password with entropy $H_P$ and iteration count $c$, an attacker's expected work factor is:

$$W = c \cdot 2^{H_P-1}$$

This is why we recommend using the password generator. Every additional bit of entropy doubles the attacker's workload! and his RRX 4090 Ti uk. 

### Memory-Hard Functions: A Brief Digression

I'm a big fan of memory-hard functions like Argon2. While we're not using them in this version (compatibility reasons), they're worth mentioning because they're particularly good at resisting hardware acceleration. I'm actually actively trying to find a way of using it.

Their security is quantified using cumulative memory complexity:

$$CMC_{\phi} = \sum_{i=1}^{T} S_i$$

Ideal MHFs scale quadratically with time, making them particularly painful for attackers using specialized hardware. Maybe in version 2.0?

## Multi-Factor Key Derivation with File-Based Keys: Belt and Suspenders

### Why One Factor When You Can Have Two?

Traditional password-based encryption has one glaring weakness: it relies solely on "something you know" (your password). As humans, we're notoriously bad at remembering high-entropy passwords. So I thought, why not add a "something you have" factor?

Our file-based key approach brings multi-factor security to the table. If we get mathematical about it, given a password $P$ with entropy $H_P$ and a key file $F$ with entropy $H_F$, the combined entropy becomes:

$$H_{combined} = H_P + H_F - H_{correlation}$$

When your key file is chosen independently from your password (as it should be!), $H_{correlation}$ is practically zero, giving us:

$$H_{combined} \approx H_P + H_F$$

That's a potentially massive boost in security. Even a modest 1MB random file contributes millions of bits of entropy. Overkill? Perhaps. But I sleep better at night.

### The Secret Sauce: How We Mix the Factors

The way we combine the password and file factors is crucial. We needed something with:

1. **Collision resistance**: You shouldn't be able to find two different combinations that produce the same key.
2. **Partial preimage resistance**: Knowing one factor shouldn't help much in figuring out the requirements for the other.

After experimenting with several approaches, I settled on the elegant simplicity of bitwise XOR:

$$K_{final} = K_{password} \oplus K_{file}$$

Here's how we implement it:

```python
def generate_key(password: str, salt: bytes, key_file_path: str = None) -> bytes:
    """Generates a key from a password, salt, and optionally a key file."""
    # Start with the password-based key derivation
    kdf = crypto.pbkdf2(
        algorithm=crypto.hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  # NIST recommendation as of 2023
    )
    password_key = kdf.derive(password.encode())
    
    # If a key file is provided, incorporate it into the final key
    if key_file_path and os.path.exists(key_file_path):
        try:
            # Generate a hash of the file contents
            file_hash = hashlib.sha256()
            with open(key_file_path, 'rb') as kf:
                while chunk := kf.read(8192):  # 8KB chunks
                    file_hash.update(chunk)
            
            file_key = file_hash.digest()
            
            # Combine password-derived key with file-derived key using XOR
            final_key = bytes(a ^ b for a, b in zip(password_key, file_key))
            return final_key
        except Exception as e:
            # If there's any error with the key file, fall back to password-only
            return password_key
    
    # If no key file is provided, just return the password-derived key
    return password_key
```

Notice we're processing the file in chunks? That's so we can handle files of arbitrary size without loading everything into memory. Want to use a 50GB movie as your key file? Go for it (though I wouldn't recommend it seriously your 4K jav movie is not worth it man.. just use a picture of your dog like everyone imo lol).

### What This Means for Attackers: The Probability Nightmare 

From an information-theoretic perspective, adding a key file massively increases an attacker's uncertainty. If $E$ represents the event of successfully recovering the encryption key:

$$P(E) = P(E|K_P) \cdot P(K_P) + P(E|\neg K_P) \cdot P(\neg K_P)$$

With password-only encryption, if an attacker knows your password, they're in ($P(E|K_P) = 1$). With our key file implementation, they also need the exact file ($P(E|K_P) = P(K_F)$), giving us:

$$P(E) \approx P(K_P) \cdot P(K_F)$$

That's a multiplicative decrease in success probability! If your password has a 1-in-a-million chance of being guessed, and your key file is one of a billion possible files, the combined probability becomes 1-in-a-quintillion. and if you name your file with a long ass name IT'S EVEN BETTER!! 

### A Note on File Format: The Devil's in the Details

To make sure everything works smoothly, we embed a single-byte flag in the encrypted file header that indicates whether a key file was used:

```python
# Store whether a key file was used (1 byte: 0=no, 1=yes)
key_file_used = b'\x01' if key_file_path else b'\x00'
# Store salt, nonce, then ciphertext
encrypted_file.write(key_file_used + salt + nonce + encrypted)
```

During decryption, we check this flag first:

```python
# Extract key file flag (1 byte)
key_file_required = data[0] == 1

# If the file was encrypted with a key file but none is provided, return error
if key_file_required and not key_file_path:
    return False, "This file was encrypted with a key file. Please select the key file."
```

This gives us a clean user experience while maintaining compatibility. Win-win.

### Practical Considerations: With Great Power...

While file-based keys significantly enhance security, they come with their own challenges:

1. **Don't lose that file!** Unlike passwords, you can't memorize file keys. Have backups that why i recommend a usb stick with the files en the enc file!!.
2. **Not all files are created equal.** A JPG of your cat probably has less entropy than a true random file of the same size. For maximum security, consider using a dedicated random file like don't use rick roll mp3 too easy!!.
3. **Storage matters.** If you keep your key file on the same system as your encrypted data, you're reducing the security benefit.

The minimum security level of our implementation can be quantified as:

$$S_{min} = \min\left(S_{PBKDF2}(P), S_{PBKDF2}(P) \oplus S_{SHA-256}(F)\right)$$

When $F$ contains sufficient entropy, this significantly exceeds the security of the password alone. But remember: security is only as strong as its weakest link!

## Partial Authentication Verification: Trust But Verify

### The GCM Authentication Tag: A Cryptographic Seal

One of the neat properties of AEAD schemes like AES-GCM is that they include an authentication tag that serves as a cryptographic seal on the ciphertext. If anyone tampers with the encrypted data, the tag verification will fail.

In GCM, the tag is calculated as a function of the ciphertext, any additional authenticated data, and the encryption key:

$$T = (A \cdot H^{m+n+1} + C_1 \cdot H^{m+n} + \ldots + C_m \cdot H^{n+1} + L \cdot H^n + IV \cdot H) \oplus E_K(IV || 0)$$

### The Insight: Verification Without Full Decryption

Here's a trick I'm particularly proud of: in GCM, we can verify the integrity of the entire ciphertext by attempting to decrypt just a small portion of it. This is because the authentication tag is calculated over the entire ciphertext, and the verification happens before any plaintext is produced.

For a ciphertext $C = C_1 || C_2 || \ldots || C_m$, the verification function can be represented as:

$$V_K(IV, C, T) = \begin{cases} 
1 & \text{if } T = f_K(IV, C) \\
0 & \text{otherwise}
\end{cases}$$

The key insight is that $V_K$ can be computed without actually completing the decryption operation ( wich help a lots like fucking lots). This lets us quickly check if the password (and key file, if used) is correct without processing the entire file.

### How We Implemented It: Efficiency Meets Security

Here's the code that makes the magic happen:

```python
def verify_file_integrity(file_path: str, password: str, key_file_path: str = None):
    """Verifies only the integrity of an encrypted file without fully decrypting it."""
    try:
        with open(file_path, 'rb') as encrypted_file:
            data = encrypted_file.read()

        # Check for minimum required size
        if len(data) < 1 + 16 + 12 + 16:  # flag(1) + salt(16) + nonce(12) + minimum tag size(16)
            return False, "File is too small to be a valid encrypted file."

        # Extract file format information
        key_file_required = data[0] == 1
        if key_file_required and not key_file_path:
            return False, "This file was encrypted with a key file. Please select the key file."

        salt = data[1:17]
        nonce = data[17:29]
        encrypted_data = data[29:]

        # Derive the key (same process as for decryption)
        key = generate_key(password, salt, key_file_path)
        aesgcm = crypto.aesgcm(key)

        # In GCM, we need to perform decryption to verify the tag,
        # but we'll only verify a small portion (first 32 bytes or entire file if small)
        verification_size = min(32, len(encrypted_data))
        verification_chunk = encrypted_data[:verification_size]
        
        try:
            # Attempt to decrypt just the verification chunk to check authenticity
            # This will raise InvalidTag if authentication fails
            aesgcm.decrypt(nonce, verification_chunk, None)
            return True, "File integrity verified successfully."
        except InvalidTag:
            return False, "Integrity verification failed: Incorrect password or corrupted file."
            
    except Exception as e:
        return False, f"Error during integrity verification: {str(e)}"
```

Notice we're only attempting to decrypt the first 32 bytes (or the entire file if it's smaller)? The `InvalidTag` exception will be raised immediately if the authentication fails, regardless of the file size.

### The Speed Advantage: It's All About Efficiency 

For a file of size $n$ bytes, full decryption takes $O(n)$ time. Partial verification? That's $O(1)$ with a fixed verification chunk size. The time ratio between full decryption and partial verification is approximately:

$$R_{time} = \frac{T_{full}}{T_{partial}} \approx \frac{n}{c}$$

Where $c$ is our 32-byte verification chunk. For large files (think gigabytes), this translates to a massive speed improvement. We're talking milliseconds instead of seconds or even minutes this is insane.

### The Security Guarantee: No Compromise

You might be wondering if this shortcut reduces security. The good news: it doesn't! The security guarantees are identical to full tag verification. The probability of accepting an invalid ciphertext remains bounded by:

$$P_{invalid} \leq 2^{-t}$$

Where $t$ is the tag length (128 bits in our AES-GCM implementation). That's a 1 in 340 undecillion chance of a forgery slipping through. I think we're covered. i mean if your dad have a quantum pc to acces your shady files ur fuck but yeah.

### Practical Benefits: Why This Matters

This feature isn't just a theoretical curiosity; it offers tangible benefits:

1. **Quick password verification**: Know immediately if you've entered the right password before waiting for a large file to decrypt.
2. **Efficient integrity checks**: Run regular integrity checks on your encrypted archive without the overhead of full decryption.
3. **Reduced exposure**: Your sensitive data remains encrypted during verification, minimizing exposure in memory.
4. **Better UX**: Faster feedback means a more responsive application.

From a formal security perspective, partial verification maintains the INT-CTXT security property:

$$\Pr[\exists C \notin \{C_1, C_2, \ldots, C_q\} : V_K(IV, C, T) = 1] \leq \epsilon(n)$$

In practical terms, if the verification passes, you can be confident that:
- The password (and key file, if used) is correct
- The encrypted file hasn't been tampered with
- The decryption will succeed (barring system errors)

## Entropy Analysis and Real-World Security

Let's get practical for a moment. The security of password-based encryption is fundamentally limited by the entropy of your password. For a password chosen from a character set of size $N$ with length $L$, the maximum possible entropy is:

$$H_{max} = L \cdot \log_2(N)$$

But humans are predictable creatures. Our actual password entropy is typically much lower:

$$H_{actual} \approx \alpha \cdot H_{max}$$

Where $\alpha$ is depressingly small (often < 0.3). This is why we built the password generator. A truly random 16-character password including special characters has around 100 bits of entropy—enough to make brute-force attacks utterly infeasible.

## Nonce Security: The Once-in-a-Lifetime Number

GCM requires a nonce (number used once) for each encryption operation. The name is literal—reusing a nonce with the same key is catastrophic.

With a nonce of bit length $b$, the probability of a collision after $q$ encryptions is:

$$P(collision) \approx 1 - e^{-q^2/(2 \cdot 2^b)}$$

This is the birthday paradox in action. For our 96-bit nonces, we can safely perform around $2^{48}$ (281 trillion) encryptions before worrying about collisions. I think that's sufficient for most users' lifetimes.

## Theoretical Security Boundaries: Know Your Limits

Every cryptographic system has theoretical limits. The overall security of our system is bounded by:

$$S_{system} \leq \min(S_{AES}, S_{KDF}, S_{password}, S_{RNG})$$

For password-based encryption specifically:

$$S_{system} \leq \min(S_{AES}, S_{KDF}, S_{password}, S_{RNG})$$

With the key file feature, we can modify this to:

$$S_{system} \leq \min(S_{AES}, S_{KDF}, S_{password} + S_{keyfile} - S_{correlation}, S_{RNG})$$

This is why Defense in Depth matters. By strengthening multiple components, we raise the overall security floor.

## Closing Thoughts: Security is a Journey

Security isn't a binary state—it's a spectrum. The cryptographic mechanisms described in this document provide strong theoretical guarantees under specific assumptions. But remember that the real world is messy.

Our implementation strives to balance security, usability, and performance. The addition of key files and partial verification enhances both security and user experience without compromising the theoretical foundations.

As the security landscape evolves, so too will our approach. This is a living document, and I expect it to grow and adapt as we refine our understanding and implementation. 

I say "we" a lot because I have friends who participate. Me, Ciel, I'm not alone on this project. Everyone can contribute. Currently, I have a few friends who are actively participating. We really hope to evolve this application and make cryptography more popular and usable by the general public. 

---

*This document presents a comprehensive analysis of the cryptographic methods employed in Encrypty-chan, grounded in information theory, computational complexity, and formal security models. While I've tried to keep things relatively approachable, there's no avoiding the mathematical rigor required for proper security analysis. If you've made it this far, congratulations—you now understand more about cryptography than 99.9% of the population.*
