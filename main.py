from cryptography.hazmat.primitives import serialization
from rsa_utils import generer_cles, crypter, decrypter, signer, verifier

if __name__ == "__main__":
    print("Bienvenue dans le programme RSA!")

    cle_privee, cle_publique = None, None

    while True:
        print("\nChoisissez une option:")
        print("1. Générer des clés")
        print("2. Crypter et signer un message")
        print("3. Décrypter et vérifier un message")
        print("4. Insérer manuellement des clés")
        print("5. Quitter")

        choix = input("Option: ")

        if choix == "1":
            cle_privee, cle_publique = generer_cles()
            print("\nClé privée:\n", cle_privee.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode())
            print("\nClé publique:\n", cle_publique.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode())

        elif choix == "2":
            if not (cle_privee and cle_publique):
                print("Vous devez d'abord générer ou insérer des clés.")
                continue
            message = input("Entrez le message que vous souhaitez crypter et signer: ")
            texte_crypte = crypter(cle_publique, message.encode())
            signature = signer(cle_privee, message.encode())
            print(f"\nMessage crypté: {texte_crypte}")
            print(f"Signature: {signature}")

        elif choix == "3":
            if not (cle_privee and cle_publique):
                print("Vous devez d'abord générer ou insérer des clés.")
                continue
            texte_crypte = eval(input("Entrez le message crypté (format bytes): "))
            signature = eval(input("Entrez la signature (format bytes): "))
            texte_clair = decrypter(cle_privee, texte_crypte)
            est_signature_valide = verifier(cle_publique, texte_clair, signature)
            print(f"\nMessage déchiffré: {texte_clair.decode()}")
            print(f"La signature est valide: {est_signature_valide}")

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

        elif choix == "5":
            print("Quitter le programme...")
            break

        else:
            print("Option non valide. Veuillez choisir une option valide.")


