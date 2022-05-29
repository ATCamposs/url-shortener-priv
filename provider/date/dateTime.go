package date

import "time"

type dateTime struct {
}

func New() DateInterface {
	time.Local, _ = time.LoadLocation("America/Sao_Paulo")
	return &dateTime{}
}

func (t *dateTime) Now() time.Time {
	return time.Now()
}

func (t *dateTime) NowInRfc3339() string {
	return time.Now().Format(time.RFC3339)
}
