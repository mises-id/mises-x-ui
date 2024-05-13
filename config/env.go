package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/caarlos0/env"
	"github.com/joho/godotenv"
	"os"
)

type Env struct {
	RootPath          string
	RawMisesPublicKey string `env:"MISES_PUBLIC_KEY" envDefault:""`
	MisesPublicKey    *rsa.PublicKey
	ServerForVpnLink  string `env:"SERVER_FOR_VPN_LINK" envDefault:""`
}

var (
	Envs *Env
)

func InitEnv() error {
	// Read public key from .env
	projectRootPath, err := os.Getwd()
	if err != nil {
		return err
	}

	envPath := projectRootPath + "/.env"
	if _, err := os.Stat(envPath); err != nil {
		//fmt.Println("Error Stat:", err)
		return err
	}
	_ = godotenv.Load(envPath)
	Envs = &Env{}
	err = env.Parse(Envs)
	if err != nil {
		return err
	}
	Envs.RootPath = projectRootPath
	
	if Envs.RawMisesPublicKey == "" {
		return fmt.Errorf("public key is empty")
	}

	// Decode the base64-encoded public key DER
	publicKeyDER, err := base64.StdEncoding.DecodeString(Envs.RawMisesPublicKey)
	if err != nil {
		return err
	}

	// Parse the public key
	Envs.MisesPublicKey, err = x509.ParsePKCS1PublicKey(publicKeyDER)
	if err != nil {
		return err
	}
	if Envs.MisesPublicKey == nil {
		return fmt.Errorf("public key is nil")
	}

	// Success
	return nil
}
