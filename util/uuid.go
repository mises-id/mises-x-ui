package util

import (
	"github.com/google/uuid"
)

func GetUuid() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
