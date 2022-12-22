package aws

import (
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/joho/godotenv"
)

func MainConsumer() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	awsQueue := os.Getenv("AWS_QUEUE")

	aws_sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	c := New(awsQueue, handle,
		&Config{
			AwsSession:                  aws_sess,
			SqsMaxNumberOfMessages:      10,
			SqsMessageVisibilityTimeout: 10,
			Receivers:                   1,
			PollDelayInMilliseconds:     100,
		})

	c.Start()

}

func handle(m *sqs.Message) error {
	tinkSecret := os.Getenv("TINK_SECRET")

	fmt.Println("Message Body:", *(m.Body))

	msg := *(m.Body)

	kh, _ := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	a, _ := aead.New(kh)

	//ct, _ := a.Encrypt([]byte(msg), []byte(tinkSecret))

	pt, _ := a.Decrypt([]byte(msg), []byte(tinkSecret))

	fmt.Printf("Cipher text: %x\nPlain Text: %s\n\n\n", msg, pt)

	expPriv := &keyset.MemReaderWriter{}
	insecurecleartextkeyset.Write(kh, expPriv)
	fmt.Printf("Key: %s\n\n", expPriv)

	return nil
}
