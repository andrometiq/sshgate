package faketg

import (
	"context"
	"sync"

	tg "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// HoldMessageResponse forces a callback to be polled before the sender can
// register the returned message ID. Install the hook before starting the API,
// use hold policy, wait for captured, explicitly release the card, and wait for
// callback handling evidence before releasing the response. Always defer release.
// Only the first actionable message response is held; edits remain available.
func HoldMessageResponse() (hook func(context.Context, tg.Message), captured <-chan tg.Message, release func()) {
	messages := make(chan tg.Message, 1)
	resume := make(chan struct{})
	var once, releaseOnce sync.Once
	hook = func(ctx context.Context, message tg.Message) {
		if message.ReplyMarkup == nil {
			return
		}
		hold := false
		once.Do(func() { hold = true; messages <- message })
		if hold {
			select {
			case <-resume:
			case <-ctx.Done():
			}
		}
	}
	return hook, messages, func() { releaseOnce.Do(func() { close(resume) }) }
}
