package c2s

import "context"

func runWriter(ctx context.Context, s *Session, shutdownFn func()) {
	defer shutdownFn()
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-s.outbound:
			if !ok {
				return
			}
			if s.smQueue != nil {
				_, _ = s.smQueue.Enqueue(raw)
			}
			if _, err := s.enc.WriteRaw(raw); err != nil {
				s.log.Error("writer: write error", "err", err)
				return
			}
		}
	}
}
