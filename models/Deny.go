package models

import "time"

type Deny struct {
	Count int
	At    time.Time
}
