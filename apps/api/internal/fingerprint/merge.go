package fingerprint

// Merge returns a new Components with client's keys overlaid by server's
// (shallow: a server key replaces the client key wholesale).
func Merge(client, server Components) Components {
	out := make(Components, len(client)+len(server))
	for k, v := range client {
		out[k] = v
	}
	for k, v := range server {
		out[k] = v
	}
	return out
}
