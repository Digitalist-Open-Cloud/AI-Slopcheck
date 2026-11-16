package main

func (l *limiter) allow(key any) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.windows[key]
}

func (c Client) Expired() bool { return time.Now().After(c.ExpiresAt) }

func (s *Store) Close() error { return s.db.Close() }

func (a *Admin) models(tags []Model) {
	for i := range tags {
		m := &tags[i]
		go func() {
			for _, line := range strings.Split(m.RawLicense, "\n") {
				if line = strings.TrimSpace(line); line != "" {
					m.License = line
					break
				}
			}
		}()
	}
}
