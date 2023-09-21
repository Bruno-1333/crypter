# Importation des modules nécessaires depuis la bibliothèque cryptography
from cryptography.hazmat.primitives import serialization
# Importation des fonctions utilitaires définies dans le module rsa_utils
from rsa_utils import generer_cles, crypter, decrypter, signer, verifier

# Assurez-vous que le script est exécuté en tant que script principal
if __name__ == "__main__":
    print("Bienvenue dans le programme RSA!")

    # Initialisation des clés à None
    cle_privee, cle_publique = None, None

    while True:
        # Affichage du menu principal
        print("\nChoisissez une option:")
        print("1. Générer des clés")
        print("2. Crypter et signer un message")
        print("3. Décrypter et vérifier un message")
        print("4. Insérer manuellement des clés")
        print("5. Quitter")

        choix = input("Option: ")

        # Génération des clés
        if choix == "1":
            cle_privee, cle_publique = generer_cles()
            # Affichage des clés générées
            print("\nClé privée:\n", cle_privee.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode())
            print("\nClé publique:\n", cle_publique.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode())

        # Chiffrement et signature d'un message
        elif choix == "2":
            # Vérification que les clés ont été générées ou insérées
            if not (cle_privee and cle_publique):
                print("Vous devez d'abord générer ou insérer des clés.")
                continue
            message = input("Entrez le message que vous souhaitez crypter et signer: ")
            texte_crypte = crypter(cle_publique, message.encode())
            signature = signer(cle_privee, message.encode())
            # Affichage du message chiffré et de la signature
            print(f"\nMessage crypté: {texte_crypte}")
            print(f"Signature: {signature}")

        # Déchiffrement et vérification d'un message
        elif choix == "3":
            # Vérification que les clés ont été générées ou insérées
            if not (cle_privee and cle_publique):
                print("Vous devez d'abord générer ou insérer des clés.")
                continue
            texte_crypte = eval(input("Entrez le message crypté (format bytes): "))
            signature = eval(input("Entrez la signature (format bytes): "))
            texte_clair = decrypter(cle_privee, texte_crypte)
            est_signature_valide = verifier(cle_publique, texte_clair, signature)
            # Affichage du message déchiffré et de la validité de la signature
            print(f"\nMessage déchiffré: {texte_clair.decode()}")
            print(f"La signature est valide: {est_signature_valide}")

        # Insertion manuelle des clés
        elif choix == "4":
            cle_privee_input = input(
                "Insérez la clé privée (au format PEM) ou laissez vide si vous ne souhaitez pas la changer: ")
            cle_publique_input = input(
                "Insérez la clé publique (au format PEM) ou laissez vide si vous ne souhaitez pas la changer: ")
            if cle_privee_input:
                cle_privee = serialization.load_pem_private_key(
                    cle_privee_input.encode(),
                    password=None
                )
            if cle_publique_input:
                cle_publique = serialization.load_pem_public_key(cle_publique_input.encode())

        # Sortie du programme
        elif choix == "5":
            print("Quitter le programme...")
            break

        else:
            # Option non reconnue
            print("Option non valide. Veuillez choisir une option valide.")




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
