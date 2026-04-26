package security

import (
	"securerelaymessager/logger"
	"time"
)

// function attempts to set a session ID as metadata. If the session ID does not exist, it will set the current timestamp as the sessionID.
func PickSessionID(sessID time.Time, peerSuggestions ...time.Time) time.Time {
	if sessID.IsZero() {
		logger.Info("Setting session ID")
		sessID = time.Now()
	}
	for _, timestamp := range peerSuggestions {
		if sessID.Compare(timestamp) == -1 {
			sessID = timestamp
		}
	}
	return sessID
}
