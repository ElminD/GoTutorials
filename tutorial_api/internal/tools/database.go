package tools

import (
	log "github.com/sirupsen/logrus"
)

// Database collections
type LoginDetails struct {
	AuthToken string
	Username string
}

type CoinDetails struct {
	Coins int64
	Username string
}

type DatabaseInterface interface {
	GetUserLoginDetails(username string) *LoginDetails 
	GetUserCoins(username string) *CoinDetails
	SetupDatabse() error
}

func NewDatabase() (*DatabaseInterface, error) {

	var database DatabaseInterface = &mockDB{}

	var err error = database.SetupDatabse()
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return &database, nil
}