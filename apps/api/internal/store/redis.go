package store

// Redis is optional and used only for rate limiting and key caching; it is
// exposed through (*Store).Redis, which returns nil when unconfigured.
