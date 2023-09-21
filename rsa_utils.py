from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generer_cles():
    cle_privee = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    cle_publique = cle_privee.public_key()
    return cle_privee, cle_publique

def crypter(cle_publique, message):
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
        return False

'''

Pour envoyer un message:
Générer des clés:

 - Choisissez cette option pour générer une paire de clés (publique et privée).
 - Vous verrez les clés affichées à l'écran. Gardez votre clé privée en sécurité et ne la partagez avec personne.
 - Partagez votre clé publique avec la personne à qui vous souhaitez envoyer un message.
 - Demandez à cette personne de partager sa clé publique avec vous.
 
Insérer manuellement des clés:

 - Choisissez cette option pour insérer manuellement la clé publique de la personne.
 - Entrez la clé publique de cette personne.

Crypter et signer un message:

 - Choisissez cette option pour crypter et signer un message.
 - Tapez votre message.
 - Le programme utilisera la clé publique que vous avez insérée pour crypter le message et votre propre clé privée pour le signer.
 - Le programme affichera le texte crypté et la signature.
 - Envoyez le texte crypté et la signature à la personne.

Pour recevoir et vérifier un message:
Générer des clés:

 - Si vous n'avez pas encore généré de paire de clés, choisissez cette option.
 - Partagez votre clé publique avec la personne qui vous enverra un message.
 - Demandez-lui de partager sa clé publique avec vous.

Insérer manuellement des clés:

 - Choisissez cette option pour insérer manuellement la clé publique de la personne.
 - Entrez la clé publique de cette personne.

Décrypter et vérifier un message:

 - Choisissez cette option lorsque vous recevez un message crypté et une signature.
 - Entrez le texte crypté et la signature.
 - Le programme utilisera votre clé privée pour décrypter le message et la clé publique de la personne pour vérifier la signature.
 -Le programme affichera le message décrypté et confirmera si la signature est valide.

'''

