package firebase

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"

	firebase "firebase.google.com/go"
	"github.com/hirokazumiyaji/firebase-auth-gae-go/auth"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/transport"
)

var firebaseScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/datastore",
	"https://www.googleapis.com/auth/devstorage.full_control",
	"https://www.googleapis.com/auth/firebase",
	"https://www.googleapis.com/auth/identitytoolkit",
	"https://www.googleapis.com/auth/userinfo.email",
}

type App struct {
	authOverride     map[string]interface{}
	creds            *google.DefaultCredentials
	dbURL            string
	projectID        string
	serviceAccountID string
	storageBucket    string
	opts             []option.ClientOption
}

func NewApp(ctx context.Context, config *firebase.Config, opts ...option.ClientOption) (*App, error) {
	o := []option.ClientOption{option.WithScopes(firebaseScopes...)}
	o = append(o, opts...)
	creds, err := transport.Creds(ctx, o...)
	if err != nil {
		return nil, err
	}
	if config == nil {
		if config, err = getConfigDefaults(); err != nil {
			return nil, err
		}
	}

	var pid string
	if config.ProjectID != "" {
		pid = config.ProjectID
	} else if creds.ProjectID != "" {
		pid = creds.ProjectID
	} else {
		pid = os.Getenv("GOOGLE_CLOUD_PROJECT")
		if pid == "" {
			pid = os.Getenv("GCLOUD_PROJECT")
		}
	}

	ao := make(map[string]interface{})
	if config.AuthOverride != nil {
		ao = *config.AuthOverride
	}

	return &App{
		authOverride:     ao,
		creds:            creds,
		dbURL:            config.DatabaseURL,
		projectID:        pid,
		serviceAccountID: config.ServiceAccountID,
		storageBucket:    config.StorageBucket,
		opts:             o,
	}, nil
}

func (a *App) Auth(ctx context.Context) (*auth.Client, error) {
	return auth.NewClient(
		ctx,
		&auth.AuthConfig{
			Creds:            a.creds,
			ProjectID:        a.projectID,
			Opts:             a.opts,
			ServiceAccountID: a.serviceAccountID,
			Version:          firebase.Version,
		},
	)
}

func getConfigDefaults() (*firebase.Config, error) {
	c := &firebase.Config{}
	confFileName := os.Getenv("FIREBASE_CONFIG")
	if confFileName == "" {
		return c, nil
	}
	var dat []byte
	if confFileName[0] == byte('{') {
		dat = []byte(confFileName)
	} else {
		var err error
		if dat, err = ioutil.ReadFile(confFileName); err != nil {
			return nil, err
		}
	}

	if err := json.Unmarshal(dat, c); err != nil {
		return nil, err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(dat, &m); err != nil {
		return nil, err
	}
	if ao, ok := m["databaseAuthVariableOverride"]; ok && ao == nil {
		var nullMap map[string]interface{}
		c.AuthOverride = &nullMap
	}
	return c, nil
}
