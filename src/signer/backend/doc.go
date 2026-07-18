// Package backend is the local Telegram approval front end: TelegramBackend
// posts each request to the operator's Telegram DM and waits for an
// inline-keyboard tap, ChatStore persists the linked DM chat_id, and
// Explainer renders optional plain-English command explanations.
// TelegramBackend implements the signerkit.Backend interface defined in
// pkg/signerkit, which also holds the other implementations (StubBackend,
// MockBackend, HostedServerBackend) and the request/result types.
//
// TelegramBackend MUST be safe for concurrent calls — the daemon serves
// multiple sign requests in parallel and a backend that serialises
// internally is acceptable, but one that races on shared state is not.
package backend
