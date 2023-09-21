# Importation des modules nécessaires depuis la bibliothèque cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generer_cles():
    # Génération de la clé privée RSA avec un exposant public de 65537 et une taille de 2048 bits
    cle_privee = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Récupération de la clé publique associée à la clé privée
    cle_publique = cle_privee.public_key()
    return cle_privee, cle_publique

def crypter(cle_publique, message):
    # Chiffrement du message avec la clé publique utilisant le padding OAEP et l'algorithme SHA256
    texte_crypte = cle_publique.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return texte_crypte

def decrypter(cle_privee, texte_crypte):
    # Déchiffrement du message chiffré avec la clé privée utilisant le même padding et algorithme que lors du chiffrement
    texte_clair = cle_privee.decrypt(
        texte_crypte,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return texte_clair

def signer(cle_privee, message):
    # Signature du message avec la clé privée utilisant le padding PSS et l'algorithme SHA256
    signature = cle_privee.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verifier(cle_publique, message, signature):
    try:
        # Vérification de la signature avec la clé publique utilisant le même padding et algorithme que lors de la signature
        cle_publique.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        # Si la vérification échoue, renvoie False
        return False



