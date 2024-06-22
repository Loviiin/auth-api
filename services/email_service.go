package services

import (
	"fmt"
)

func SendResetPasswordEmail(email, token string) error {
	// Simulação do envio de email
	fmt.Printf("Enviando email para %s com o token de reset de senha: %s\n", email, token)
	return nil
}
