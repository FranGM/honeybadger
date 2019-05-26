package main

func negotiationResponse(spi uint32, keyHalf []byte) NetworkRequest {
	response := NetworkRequest{
		SPI:        spi,
		EncryptKey: keyHalf,
	}

	return response
}

func assembleEncryptKey(firstHalf []byte, secondHalf []byte) []byte {
	encryptKey := make([]byte, len(firstHalf))
	copy(firstHalf, encryptKey)
	encryptKey = append(encryptKey, secondHalf...)

	return encryptKey
}
