# gloo-gateway-extauth-sec

Een Go-securitymodule voor het ondertekenen van JSON Web Tokens (JWT's) binnen
custom ExtAuth-services achter Gloo Gateway. De module geeft tokenvarianten uit
die in de basis identiek zijn (zelfde header, zelfde registered claims, zelfde
ondertekening) en uitsluitend in hun domeinspecifieke claims verschillen. Drie
varianten zitten ingebouwd:

- **eIDAS** — de Europese standaard voor grensoverschrijdende authenticatie
- **DigiD** — authenticatie van burgers (Logius)
- **eHerkenning** — authenticatie van organisaties en handelende personen

Daarnaast kunnen consumers van deze library hun **eigen tokentype** definiëren
via `IssueCustom`, zonder de library aan te passen. Zo blijft de module vrij van
organisatiespecifieke varianten (zie [Custom tokentype](#custom-tokentype)).

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
- `pkg/token.Service` — biedt per ingebouwde variant een `Issue...`-methode plus
  het generieke `IssueCustom` voor eigen tokentypes.

### Claim-indeling

De OIDC-standaardclaims staan op het hoogste niveau (`iss`, `sub`, `aud`, `exp`,
`nbf`, `iat`, `jti`, en waar van toepassing `acr`, `amr`, `auth_time`). De
variantspecifieke gegevens staan genest onder een eigen sleutel (`eidas`,
`digid`, `eherkenning`, of bij een custom variant een door de consumer gekozen
sleutel). De private claim `token_type` benoemt het tokentype expliciet.

De naam van die claim is configureerbaar via `WithTokenTypeClaim` (standaard
`token_type`), zodat organisaties hun eigen collision-resistant namespace
(RFC 7519 §4.3) kunnen gebruiken, bijvoorbeeld `example_token_type`.

De `acr`-claim wordt gevuld met de eIDAS LoA-URI: direct bij eIDAS, afgeleid bij
DigiD en eHerkenning (zie de `EIDAS()`-mappings). Bij een custom variant bepaalt
de consumer zelf de `acr`-waarde (optioneel).

### Custom tokentype

Een applicatie die deze library gebruikt kan een eigen tokentype uitgeven zonder
de library te wijzigen. De payload is een gewone struct die de consumer zelf
bezit; implementeert die een `Validate() error`, dan wordt die vóór ondertekening
aangeroepen. De `ClaimsKey` mag niet botsen met een gereserveerde claim.

```go
type AcmeClaims struct {
	EmployeeID string   `json:"employee_id"`
	Roles      []string `json:"roles,omitempty"`
}

func (p AcmeClaims) Validate() error {
	if p.EmployeeID == "" {
		return errors.New("employee_id ontbreekt")
	}
	return nil
}

jwt, err := svc.IssueCustom(token.CustomRequest{
	CommonRequest: token.CommonRequest{Subject: "emp-00421", Audience: []string{"acme-portal-api"}},
	Type:          "acme-portal", // waarde van de token_type-claim
	ClaimsKey:     "acme-portal", // sleutel waaronder de payload genest wordt
	ACR:           "",            // optioneel
	Claims:        AcmeClaims{EmployeeID: "00421", Roles: []string{"beheerder"}},
})
```

## Installatie

```sh
go get github.com/jwt-extauth/gloo-gateway-extauth-sec
```

Vereist Go 1.22 of nieuwer.

## Gebruik

```go
package main

import (
	"fmt"
	"log"

	extauthsec "github.com/jwt-extauth/gloo-gateway-extauth-sec"
	"github.com/jwt-extauth/gloo-gateway-extauth-sec/pkg/claims"
	"github.com/jwt-extauth/gloo-gateway-extauth-sec/pkg/token"
)

func main() {
	signer, err := extauthsec.NewSigner(
		extauthsec.WithIssuer("https://extauth.example.org"),
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

Een volledig werkend voorbeeld dat de drie ingebouwde varianten plus een custom
variant uitgeeft, de JWKS toont en een token verifieert staat in
[`examples/basic`](examples/basic/main.go):

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
