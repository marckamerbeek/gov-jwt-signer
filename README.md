# gloo-gateway-extauth-sec

Een Go-securitymodule voor het ondertekenen van JSON Web Tokens (JWT's) binnen
custom ExtAuth-services achter Gloo Gateway. De module geeft vier tokenvarianten
uit die in de basis identiek zijn (zelfde header, zelfde registered claims, zelfde
ondertekening) en uitsluitend in hun domeinspecifieke claims verschillen:

- **Medewerkersportaal** — intern gebruik
- **eIDAS** — de Europese standaard voor grensoverschrijdende authenticatie
- **DigiD** — authenticatie van burgers (Logius)
- **eHerkenning** — authenticatie van organisaties en handelende personen

De module is opgezet rond bestaande standaarden en met een minimaal
supply-chain-oppervlak: de enige externe afhankelijkheid is
[`golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt). JWK, JWKS en de
RFC 7638-thumbprint zijn met de standaardbibliotheek geïmplementeerd.

## Standaarden

| Onderwerp | Standaard |
|-----------|-----------|
| JWT | RFC 7519 |
| JWS (ondertekening) | RFC 7515 |
| JWK / JWKS | RFC 7517 |
| Algoritmen | RFC 7518 |
| JWK Thumbprint (kid) | RFC 7638 |
| Authentication Method References (amr) | RFC 8176 |
| eIDAS minimum data set | eIDAS SAML Attribute Profile (Verordening (EU) 910/2014) |
| Betrouwbaarheidsniveaus (acr) | eIDAS LoA low/substantial/high |
| eHerkenning | Afsprakenstelsel eToegang |

Het standaardalgoritme is **RS256**, conform de baseline van het NL GOV Assurance
profile voor OAuth 2.0. Via `WithAlgorithm` kan worden gewisseld naar onder andere
PS256 of ES256.

## Architectuur

De module is in lagen opgebouwd zodat de domeinmodellen losstaan van de
JOSE-implementatie:

```
extauthsec/                rootpackage: Signer, Verifier, sleutel- en JWKS-logica
├── pkg/claims/            typed claim-structs + betrouwbaarheidsniveaus (geen externe deps)
└── pkg/token/             Service die per variant claims samenstelt en ondertekent
```

- `extauthsec.Signer` — onveranderlijk en concurrency-safe; ondertekent een
  willekeurige `jwt.Claims` en publiceert de bijbehorende JWKS.
- `extauthsec.Verifier` — valideert uitgegeven tokens (kid-matching,
  algoritme-allowlist tegen algorithm-confusion, exp/nbf, iss/aud). Bedoeld voor
  zelftest en lichte verificatie; productie-verifiers in andere diensten gebruiken
  hun eigen JOSE-bibliotheek.
- `pkg/token.Service` — biedt per variant een `Issue...`-methode.

### Claim-indeling

De OIDC-standaardclaims staan op het hoogste niveau (`iss`, `sub`, `aud`, `exp`,
`nbf`, `iat`, `jti`, en waar van toepassing `acr`, `amr`, `auth_time`). De
variantspecifieke gegevens staan genest onder een eigen sleutel
(`medewerkersportaal`, `eidas`, `digid`, `eherkenning`). De private claim
`cjib_token_type` benoemt het tokentype expliciet.

De `acr`-claim wordt gevuld met de eIDAS LoA-URI: direct bij eIDAS, afgeleid bij
DigiD en eHerkenning (zie de `EIDAS()`-mappings), en leeg bij het medewerkersportaal.

## Installatie

```sh
go get github.com/cjib/gloo-gateway-extauth-sec
```

Vereist Go 1.22 of nieuwer.

## Gebruik

```go
package main

import (
	"fmt"
	"log"

	extauthsec "github.com/cjib/gloo-gateway-extauth-sec"
	"github.com/cjib/gloo-gateway-extauth-sec/pkg/claims"
	"github.com/cjib/gloo-gateway-extauth-sec/pkg/token"
)

func main() {
	signer, err := extauthsec.NewSigner(
		extauthsec.WithIssuer("https://extauth.cjib.nl"),
		extauthsec.WithSigningKeyFile("/etc/extauth/signing-key.pem"),
		// extauthsec.WithAlgorithm(extauthsec.PS256), // optioneel
	)
	if err != nil {
		log.Fatal(err)
	}

	svc, err := token.NewService(signer)
	if err != nil {
		log.Fatal(err)
	}

	jwt, err := svc.IssueEIDAS(token.EIDASRequest{
		CommonRequest: token.CommonRequest{
			Subject:  "NL/NL/123456789",
			Audience: []string{"urn:dienst:afnemer"},
			AMR:      []string{"pwd", "mfa"},
		},
		LoA: claims.LoAHigh,
		Person: claims.EIDAS{
			PersonIdentifier: "NL/NL/123456789",
			FamilyName:       "De Vries",
			GivenName:        "Anna",
			DateOfBirth:      "1990-05-17",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(jwt)

	// Publiceer de JWKS op het bekende endpoint.
	jwksJSON, _ := signer.JWKSJSON()
	fmt.Println(string(jwksJSON))
}
```

Een volledig werkend voorbeeld dat alle vier varianten uitgeeft, de JWKS toont en
een token verifieert staat in [`examples/basic`](examples/basic/main.go):

```sh
go run ./examples/basic
```

## Sleutelbeheer

- Lever de private sleutel als PEM aan via `WithSigningKeyPEM` (bytes) of
  `WithSigningKeyFile` (pad). PKCS#8, PKCS#1 en SEC1 worden ondersteund.
- De `kid` wordt standaard berekend als de RFC 7638-thumbprint van de publieke
  sleutel, zodat sleutelrotatie eenduidig en cache-vriendelijk verloopt. Met
  `WithKeyID` kan een eigen `kid` worden opgegeven.
- Publiceer `signer.JWKS()` / `signer.JWKSJSON()` op een JWKS-endpoint zodat
  afnemers de handtekening kunnen valideren.

## Ontwikkeling

```sh
make build     # compileren
make test      # tests met race detector en coverage
make vet       # go vet
make lint      # golangci-lint (indien geïnstalleerd)
make vuln      # govulncheck
make tidy      # go mod tidy
```

## Beveiliging

Zie [SECURITY.md](SECURITY.md) voor het melden van kwetsbaarheden en de
beveiligingsuitgangspunten van deze module.

## Licentie

Uitgebracht onder de **EUPL-1.2**. Zie [LICENSE](LICENSE).
