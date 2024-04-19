from secrets import token_bytes
from cryptography.hazmat.primitives import hashes, hmac, constant_time, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
"""
COMP4722: Network Security
Implement the following functions using the Python secrets and cryptography libraries.
The input and output variables, and expected types are given as comments in each function.

The implementation should thoroughly check for any errors/exceptions that may be generated
during runtime. The functions should never raise an exception of any type other than the
CryptoException class defined below. This way we can ensure that we have considered the
different types of errors/exceptions that can arise in the implementation. Errors can be
malformed input errors, incorrect key sizes, etc. and exceptions can be ones created by your
implementation and also from the used libraries.

All random numbers used in your implementation should be generated using your implemented
generate_random_securely() function

"""


class CryptoException(Exception):
    '''
    Custom exception class
    The below functions should raise exceptions of this class when any error is encountered.
    The code from this file should never raise an exception of any other class.
    Example usage:
        try:
            ...
        except TypeError:
            raise CryptoException("Data value must be in bytes")
    '''
    pass


################# BEGIN TODO

def generate_random_securely(size=None):
    if size is None:
        raise CryptoException("Size must be specified")
    try:
        return token_bytes(size)
    except ValueError:
        raise CryptoException("Size must be a positive integer")


def hash_message(data, hash_method):
    if hash_method not in ["SHA256", "SHA512"]:
        raise CryptoException("Invalid hash method")
    digest = hashes.Hash(getattr(hashes, hash_method)(), backend=default_backend())
    digest.update(data)
    return digest.finalize()


def hmac_message(data, hash_method, key):
    if hash_method not in ["SHA256", "SHA512"]:
        raise CryptoException("Invalid hash method")
    h = hmac.HMAC(key, getattr(hashes, hash_method)(), backend=default_backend())
    h.update(data)
    return h.finalize()


def verify_hash(data, hash_method, mac):
    if hash_method not in ["SHA256", "SHA512"]:
        raise CryptoException("Invalid hash method")
    digest = hashes.Hash(getattr(hashes, hash_method)(), backend=default_backend())
    digest.update(data)
    return constant_time.bytes_eq(digest.finalize(), mac)


def verify_hmac(data, hash_method, key, mac):
    if hash_method not in ["SHA256", "SHA512"]:
        raise CryptoException("Invalid hash method")
    h = hmac.HMAC(key, getattr(hashes, hash_method)(), backend=default_backend())
    h.update(data)
    try:
        h.verify(mac)
        return True
    except InvalidSignature:
        return False


def pad_data(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def sym_encrypt(data, sym_key, algo, chain_mode, mac_key=None, mac_mode=None):
    try:
        # Validate key lengths
        if algo == "AES128" and len(sym_key) != 16:
            raise CryptoException("AES sym_key must be 128 bits (16 bytes)")
        elif algo == "ChaCha20" and len(sym_key) != 32:
            raise CryptoException("ChaCha20 sym_key must be 256 bits (32 bytes)")

        # Validate chaining mode
        if chain_mode not in ["CBC", "CTR", "GCM"]:
            raise CryptoException("Invalid chaining mode")

        # Generate IV/nonce securely
        if chain_mode == "GCM" and algo == "AES128":
            iv_length = 12  # GCM mode requires a 12-byte nonce
        else:
            iv_length = 16  # IV length for AES/CBC and ChaCha20

        iv = generate_random_securely(iv_length)

        # Select encryption algorithm and mode
        if algo == "AES128":
            algorithm = algorithms.AES(sym_key)
            # Pad the data if necessary
            if chain_mode in ["CBC", "CTR"]:
                data = pad_data(data, 16)  # Pad to AES block size (16 bytes)
                if chain_mode == "CBC":
                    mode = modes.CBC(iv)
                elif chain_mode == "CTR":
                    mode = modes.CTR(iv)
            elif chain_mode == "GCM":
                mode = modes.GCM(iv)
            else:
                raise CryptoException("Invalid chaining mode for AES")
        elif algo == "ChaCha20":
            algorithm = algorithms.ChaCha20(sym_key, iv)
            if chain_mode in ["CBC", "CTR", "GCM"]:
                mode = None
            else:
                raise CryptoException("Invalid chaining mode for ChaCha20")
        else:
            raise CryptoException("Invalid algorithm")

        # Perform encryption
        cipher = Cipher(algorithm, mode, backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()

        # Compute MAC if mac_mode is specified
        mac = None
        if mac_mode:
            if algo == "AES128" and chain_mode == "GCM":
                mac = encryptor.tag
            elif mac_key:
                h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
                h.update(ct)
                mac = h.finalize()

        return iv, ct, mac

    except Exception as e:
        raise CryptoException("Error during encryption: {}".format(str(e)))


def sym_decrypt(data, sym_key, iv, algo, chain_mode, mac_key=None, mac=None, mac_mode=None):
    try:
        if algo == "AES128":
            if len(sym_key) != 16:
                raise CryptoException("AES key must be 128 bits (16 bytes)")
            if chain_mode == "CBC":
                cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv), backend=default_backend())
            elif chain_mode == "CTR":
                cipher = Cipher(algorithms.AES(sym_key), modes.CTR(iv), backend=default_backend())
            elif chain_mode == "GCM":
                cipher = Cipher(algorithms.AES(sym_key), modes.GCM(iv, mac), backend=default_backend())
            else:
                raise CryptoException("Invalid chaining mode")
        elif algo == "ChaCha20":
            if len(sym_key) != 32:
                raise CryptoException("ChaCha20 key must be 256 bits (32 bytes)")
            if chain_mode in ["CBC", "CTR", "GCM"]:
                cipher = Cipher(algorithms.ChaCha20(sym_key, iv), mode=None, backend=default_backend())
            else:
                raise CryptoException("Invalid chaining mode")
        else:
            raise CryptoException("Invalid algorithm")

        decryptor = cipher.decryptor()
        pt = decryptor.update(data) + decryptor.finalize()

        if mac_mode:
            if algo == "AES128" and chain_mode == "GCM":
                # For AES128-GCM, verify the MAC against the one expected by GCM
                mac = mac
                if mac != decryptor._tag:
                    raise CryptoException("Invalid MAC")
            elif mac_key:
                computed_mac = hmac_message(data, "SHA256", mac_key)
                if not constant_time.bytes_eq(computed_mac, mac):
                    raise CryptoException("MAC verification failed")

        return pt
    except InvalidSignature:
        raise CryptoException("Invalid MAC")
    except Exception as e:
        raise CryptoException("Error during decryption: {}".format(str(e)))


def gen_rsa_keypair(size):
    try:
        if size != 2048:
            raise CryptoException("Key size is not 2048")
        pr = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size, backend=default_backend()
        )
        pu = pr.public_key()
        return pu, pr
    except TypeError:
        raise CryptoException("Invalid key size")

def gen_ec_keypair():
    try:
        pr = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pu = pr.public_key()
        return pu, pr
    except Exception:
        raise CryptoException("Error generating EC keypair")


def save_public_key(public_key, file):
    try:
        # Check if public_key is an instance of RSAPublicKey or EllipticCurvePublicKey
        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise CryptoException("Invalid public key type")

        # Check if file is a string
        if not isinstance(file, str):
            raise CryptoException("File name must be a string")

        with open(file, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    except Exception:
        raise CryptoException("Error saving public key to file")


def save_private_key(private_key, file, password=None):
    try:
        # Check if private_key is an instance of RSAPrivateKey or EllipticCurvePrivateKey
        if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise CryptoException("Invalid private key type")

        # Check if file is a string
        if not isinstance(file, str):
            raise CryptoException("File name must be a string")

        encryption_algorithm = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        with open(file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ))
    except Exception:
        raise CryptoException("Error saving private key to file")

def load_public_key(file):
    try:
        # Check if file is a string
        if not isinstance(file, str):
            raise CryptoException("File name must be a string")

        with open(file, "rb") as f:
            public_key_bytes = f.read()
            public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
            return public_key
    except Exception:
        raise CryptoException("Error loading public key from file")


def load_private_key(file, password=None):
    try:
        # Check if file is a string
        if not isinstance(file, str):
            raise CryptoException("File name must be a string")

        with open(file, "rb") as f:
            private_key_bytes = f.read()
            if password:
                decryption_algorithm = serialization.BestAvailableEncryption(password)
            else:
                decryption_algorithm = serialization.NoEncryption()
            private_key = serialization.load_pem_private_key(private_key_bytes, password=password, backend=default_backend())
            return private_key
    except Exception:
        raise CryptoException("Error loading private key from file")


def rsa_encrypt(data, public_key):
    try:
        # Check if data is bytes
        if not isinstance(data, bytes):
            raise CryptoException("Data must be in bytes")
        
        # Check if public_key is an RSAPublicKey instance
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CryptoException("Invalid public key type")

        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return bytes(ciphertext)
    except Exception:
        raise CryptoException("Error encrypting data with RSA")

def rsa_decrypt(data, private_key):
    try:
        # Check if data is bytes
        if not isinstance(data, bytes):
            raise CryptoException("Data must be in bytes")

        # Check if private_key is an RSAPrivateKey instance
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise CryptoException("Invalid private key type")

        plaintext = private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    except Exception:
        raise CryptoException("Error decrypting data with RSA")


def rsa_envelope_encrypt(data, public_key):
    try:
        # Check if data is bytes
        if not isinstance(data, bytes):
            raise CryptoException("Data must be in bytes")

        # Check if public_key is an RSAPublicKey instance
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CryptoException("Invalid public key type")

        # Generate a random symmetric key for AES encryption
        symmetric_key = generate_random_securely(16)  # 16 bytes for AES128

        # Generate a random IV (Initialization Vector) for AES encryption
        iv = generate_random_securely(16)  # 16 bytes for AES IV

        # Encrypt the data using AES encryption with the symmetric key and GCM mode
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()

        # Encrypt the symmetric key using RSA encryption with the provided public key
        key_ct = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Compute the GCM authentication tag (MAC) on the encrypted data
        mac = encryptor.tag

        return key_ct, iv, ct, mac
    except Exception:
        raise CryptoException("Error encrypting data with RSA envelope")


def rsa_envelope_decrypt(data, key_data, iv, mac, private_key):
    try:
        # Check if key_data, iv, and mac are bytes
        if not all(isinstance(item, bytes) for item in [key_data, iv, mac]):
            raise CryptoException("Key data, IV, and MAC must be in bytes")

        # Check if private_key is an RSAPrivateKey instance
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise CryptoException("Invalid private key type")

        # Decrypt the symmetric key using RSA decryption with the provided private key
        symmetric_key = private_key.decrypt(
            key_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Use the decrypted symmetric key and IV to decrypt the data using AES128-GCM
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, mac), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(data) + decryptor.finalize()

        # Verify the authenticity of the decrypted data by comparing the MAC with the provided MAC
        if decryptor._tag != mac:
            raise CryptoException("Invalid MAC")

        return plaintext
    except Exception:
        raise CryptoException("Error decrypting data with RSA envelope")


def generate_signature(data, method, private_key):
    try:
        # Check if data is bytes
        if not isinstance(data, bytes):
            raise CryptoException("Data value must be in bytes")

        # Check if method is either "RSA" or "ECDSA"
        if method not in ["RSA", "ECDSA"]:
            raise CryptoException("Invalid signing method. Must be 'RSA' or 'ECDSA'")

        if method == "RSA":
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif method == "ECDSA":
            signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

        return (data, signature)
    except Exception:
        raise CryptoException("Error generating signature")

def verify_signature(data, method, public_key, signature):
    try:
        # Check if data is bytes
        if not isinstance(data, bytes):
            raise CryptoException("Data value must be in bytes")

        # Check if method is either "RSA" or "ECDSA"
        if method not in ["RSA", "ECDSA"]:
            raise CryptoException("Invalid signing method. Must be 'RSA' or 'ECDSA'")

        if method == "RSA":
            try:
                public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            except Exception:
                return False
        elif method == "ECDSA":
            try:
                public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:
                return False
    except Exception:
        raise CryptoException("Error verifying signature")

################# END TODO


def print_ba(b, prefix=''):
    '''
    Print byte string as hex string in the format:
         [prefix] <hex string> (<bit length of input>)

    :param b: byte string (byte string)
    :param prefix: prefix to be printed before the hex string (string)
    '''
    print(prefix, end="")
    if b is not None:
        print('0x' + ''.join(format(x, '02x') for x in b), end="")
        print(' (' + str(len(b) * 8) + ' bits)')
    else:
        print('None')


if __name__ == "__main__":

    # Test hash_message function
    data = b"Hello, World!"
    hash_method = "SHA256"
    hashed_data = hash_message(data, hash_method)
    print("Hashed data:", hashed_data.hex())

    # Test hmac_message function
    key = generate_random_securely(16)
    hmac_data = hmac_message(data, hash_method, key)
    print("\nHMAC data:", hmac_data.hex())

    # Test verify_hash function
    is_hash_valid = verify_hash(data, hash_method, hashed_data)
    print("\nIs hash valid?", is_hash_valid)

    # Test verify_hmac function
    is_hmac_valid = verify_hmac(data, hash_method, key, hmac_data)
    print("\nIs HMAC valid?", is_hmac_valid)

    # Test sym_encrypt and sym_decrypt functions
    sym_key = bytes(generate_random_securely(16))
    data = b"Hello World!1234"
    iv, ct, mac = sym_encrypt(data, sym_key, "AES128", "GCM", mac_key=key, mac_mode="ETM")
    print("\nEncrypted data using AES128/ChaCha20 with Chain Mode(CBC, CTR or GCM):", ct.hex())

    decrypted_data = sym_decrypt(ct, sym_key, iv, "AES128", "GCM", mac_key=key, mac=mac, mac_mode="ETM")
    print("\nDecrypted data:", decrypted_data.decode('utf-8'))

    # Test gen_ec_keypair function
    ec_public_key, ec_private_key = gen_ec_keypair()
    print("\nGenerated EC keypair:")
    print("Public key:", ec_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())
    print("Private key:", ec_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # Assuming private key is not encrypted
    ).decode())

    # Test gen_rsa_keypair function
    rsa_public_key, rsa_private_key = gen_rsa_keypair(2048)
    print("\nGenerated RSA keypair:")
    print("Public key:", rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())
    print("Private key:", rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # Assuming private key is not encrypted
    ).decode())

    # Test save_public_key and load_public_key functions
    save_public_key(ec_public_key, "public_key.pem")
    loaded_public_key = load_public_key("public_key.pem")
    print("\nLoaded RSA or EC public key:", loaded_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())

    # Test save_private_key and load_private_key functions
    save_private_key(ec_private_key, "private_key.pem")
    loaded_private_key = load_private_key("private_key.pem")
    print("\nLoaded RSA or EC private key:", loaded_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # Assuming private key is not encrypted
    ).decode())

    # Test rsa_encrypt function
    rsa_ciphertext = rsa_encrypt(b"Hello World", rsa_public_key)
    print("\nRSA Encrpted CipherText:")
    print(rsa_ciphertext.hex())

    # Test rsa_decrypt function
    plaintext = rsa_decrypt(rsa_ciphertext, rsa_private_key)
    print("\nRSA Decrypted Plaintext:")
    print(plaintext)

    # Test rsa_envelope_encrypt function
    key_ct, iv, ct, mac = rsa_envelope_encrypt(b"Hello World!", rsa_public_key)
    print("\nCiphertext of Symmetric Key (key_ct):", key_ct.hex())
    print("Initialization Vector (iv):", iv.hex())
    print("Ciphertext of Data (ct):", ct.hex())
    print("MAC (mac):", mac.hex())

    # Test rsa_envelope_decrypt function
    rsa_envelope_plaintext = rsa_envelope_decrypt(ct, key_ct, iv, mac, rsa_private_key)
    print("\nDecrypted plaintext:", rsa_envelope_plaintext)

    # Test generate_signature function using RSA or ECDSA
    file, signature = generate_signature(b"Hello World!", "ECDSA", ec_private_key)
    print("\nSignature using RSA or ECDSA:", signature.hex())

    # Test verify_signature function
    verification_result = verify_signature(file, "ECDSA", ec_public_key, signature)
    print("\nSignature Verification Result:", verification_result)