# Beveiliging

## Kwetsbaarheden melden

Meld vermoedelijke kwetsbaarheden niet via een publieke issue, maar via het interne
security-kanaal van CJIB. Geef waar mogelijk een reproduceerbaar scenario en de
impact mee. Je ontvangt zo snel mogelijk een bevestiging van ontvangst.

## Uitgangspunten

Deze module is bewust ontworpen met een klein aanvalsoppervlak:

- **Minimale afhankelijkheden.** De enige externe dependency is
  `github.com/golang-jwt/jwt/v5`. JWK, JWKS en de RFC 7638-thumbprint zijn met de
  Go-standaardbibliotheek geïmplementeerd. Dit beperkt de supply-chain-risico's.
- **Algorithm-confusion-bescherming.** De `Verifier` hanteert een
  algoritme-allowlist op basis van de JWKS. Tokens met `alg: none` of een afwijkend
  algoritme worden geweigerd.
- **Sleutel- en algoritmecontrole.** Bij het aanmaken van een `Signer` wordt
  gecontroleerd dat het sleuteltype past bij het gekozen algoritme (RSA bij RS*/PS*,
  EC bij ES*).
- **Veilige defaults.** RS256 als baseline (NL GOV Assurance profile), verplichte
  `exp`, en een `jti` met 128 bits cryptografische entropie per token.

## Sleutelbeheer

Private sleutels horen niet in de repository thuis. Lever ze via een secret store
of gemounte file aan (`WithSigningKeyFile` / `WithSigningKeyPEM`). De `.gitignore`
sluit veelvoorkomende sleutelextensies uit als extra vangnet.

## Geondersteunde versies

Beveiligingsupdates worden geleverd voor de meest recente minor-release. Houd de
Go-toolchain en `golang-jwt/jwt/v5` actueel; de CI draait `govulncheck` en een
Trivy-scan op elke push en pull request.
