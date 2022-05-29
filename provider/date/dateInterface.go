package date

import "time"

type DateInterface interface {
	Now() time.Time
	NowInRfc3339() string
}
