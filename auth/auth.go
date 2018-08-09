package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	firebaseAuth "firebase.google.com/go/auth"
	"github.com/SermoDigital/jose/jws"
	"golang.org/x/oauth2/google"
	identitytoolkit "google.golang.org/api/identitytoolkit/v3"
	"google.golang.org/api/option"
	"google.golang.org/api/transport"
	"google.golang.org/appengine/urlfetch"
)

const (
	firebaseAudience = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
	issuerPrefix     = "https://securetoken.google.com/"
)

type AuthConfig struct {
	Opts             []option.ClientOption
	Creds            *google.DefaultCredentials
	ProjectID        string
	ServiceAccountID string
	Version          string
}

type Client struct {
	is        *identitytoolkit.Service
	hc        *http.Client
	projectID string
	version   string
}

func NewClient(ctx context.Context, conf *AuthConfig) (*Client, error) {
	hc, _, err := transport.NewHTTPClient(ctx, conf.Opts...)
	if err != nil {
		return nil, err
	}
	is, err := identitytoolkit.New(hc)
	if err != nil {
		return nil, err
	}
	return &Client{
		is:        is,
		hc:        urlfetch.Client(ctx),
		projectID: conf.ProjectID,
		version:   "Go/Admin/" + conf.Version,
	}, nil
}

func (c *Client) VerifyIDToken(ctx context.Context, idToken string) (*firebaseAuth.Token, error) {
	if c.projectID == "" {
		return nil, errors.New("project id not available")
	}
	if idToken == "" {
		return nil, fmt.Errorf("id token must be a non-empty string")
	}

	t, err := verifyToken(c.hc, idToken)
	if err != nil {
		return nil, err
	}

	var payload firebaseAuth.Token
	claims := t.Payload().(jws.Claims)

	header := t.Protected()
	kid, _ := header["kid"]
	alg, _ := header["alg"]
	payload.Issuer, _ = claims.Issuer()
	audience, _ := claims.Audience()
	payload.Audience = audience[0]
	expires, _ := claims.Expiration()
	payload.Expires = expires.Unix()
	issuedAt, _ := claims.IssuedAt()
	payload.IssuedAt = issuedAt.Unix()
	payload.Subject, _ = claims.Subject()

	// Delete standard claims from the custom claims maps.
	claims.RemoveIssuer()
	claims.RemoveAudience()
	claims.RemoveExpiration()
	claims.RemoveIssuedAt()
	claims.RemoveSubject()
	claims.Del("uid")
	payload.Claims = map[string]interface{}(claims)

	projectIDMsg := "make sure the ID token comes from the same Firebase project as the credential used to" +
		" authenticate this SDK"
	verifyTokenMsg := "see https://firebase.google.com/docs/auth/admin/verify-id-tokens for details on how to " +
		"retrieve a valid ID token"
	issuer := issuerPrefix + c.projectID

	if kid == "" {
		if payload.Audience == firebaseAudience {
			err = fmt.Errorf("expected an ID token but got a custom token")
		} else {
			err = fmt.Errorf("ID token has no 'kid' header")
		}
	} else if alg != "RS256" {
		err = fmt.Errorf(
			"ID token has invalid algorithm; expected 'RS256' but got %q; %s",
			alg,
			verifyTokenMsg,
		)
	} else if payload.Audience != c.projectID {
		err = fmt.Errorf(
			"ID token has invalid 'aud' (audience) claim; expected %q but got %q; %s; %s",
			c.projectID,
			payload.Audience,
			projectIDMsg,
			verifyTokenMsg,
		)
	} else if payload.Issuer != issuer {
		err = fmt.Errorf(
			"ID token has invalid 'iss' (issuer) claim; expected %q but got %q; %s; %s",
			issuer,
			payload.Issuer,
			projectIDMsg,
			verifyTokenMsg,
		)
	} else if payload.IssuedAt > time.Now().Unix() {
		err = fmt.Errorf("ID token issued at future timestamp: %d", payload.IssuedAt)
	} else if payload.Expires < time.Now().Unix() {
		err = fmt.Errorf("ID token has expired at: %d", payload.Expires)
	} else if payload.Subject == "" {
		err = fmt.Errorf("ID token has empty 'sub' (subject) claim; %s", verifyTokenMsg)
	} else if len(payload.Subject) > 128 {
		err = fmt.Errorf(
			"ID token has a 'sub' (subject) claim longer than 128 characters; %s",
			verifyTokenMsg,
		)
	}

	if err != nil {
		return nil, err
	}
	payload.UID = payload.Subject
	return &payload, nil
}
