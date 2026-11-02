package server

import "sync"

type queueStats struct {
	Depth, Bytes, HighWater, HighWaterBytes, Limit, ByteLimit int
	Dropped                                                   uint64
}

// dynamicQueue grows with demand up to explicit count and byte limits. The
// limits keep a stalled consumer from turning a burst into unbounded memory.
type dynamicQueue[T any] struct {
	mu                               sync.Mutex
	items                            []T
	bytes, highWater, highWaterBytes int
	limit, byteLimit                 int
	dropped                          uint64
	closed                           bool
	notify                           chan struct{}
	size                             func(T) int
}

func newDynamicQueue[T any](limit, byteLimit int, size func(T) int) *dynamicQueue[T] {
	return &dynamicQueue[T]{limit: limit, byteLimit: byteLimit, size: size, notify: make(chan struct{}, 1)}
}

func (q *dynamicQueue[T]) push(value T) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	if q.size != nil {
		n = q.size(value)
	}
	if q.closed || len(q.items) >= q.limit || q.byteLimit > 0 && q.bytes+n > q.byteLimit {
		q.dropped++
		return false
	}
	q.items = append(q.items, value)
	q.bytes += n
	if len(q.items) > q.highWater {
		q.highWater = len(q.items)
	}
	if q.bytes > q.highWaterBytes {
		q.highWaterBytes = q.bytes
	}
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}

func (q *dynamicQueue[T]) pop(done <-chan struct{}) (T, bool) {
	var zero T
	for {
		q.mu.Lock()
		if len(q.items) != 0 {
			value := q.items[0]
			q.items[0] = zero
			q.items = q.items[1:]
			if q.size != nil {
				q.bytes -= q.size(value)
			}
			more := len(q.items) != 0
			q.mu.Unlock()
			if more {
				select {
				case q.notify <- struct{}{}:
				default:
				}
			}
			return value, true
		}
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return zero, false
		}
		select {
		case <-done:
			return zero, false
		case <-q.notify:
		}
	}
}

func (q *dynamicQueue[T]) close(discard bool) {
	q.mu.Lock()
	q.closed = true
	if discard {
		var zero T
		for i := range q.items {
			q.items[i] = zero
		}
		q.items = nil
		q.bytes = 0
	}
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *dynamicQueue[T]) stats() queueStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	return queueStats{Depth: len(q.items), Bytes: q.bytes, HighWater: q.highWater, HighWaterBytes: q.highWaterBytes, Limit: q.limit, ByteLimit: q.byteLimit, Dropped: q.dropped}
}
