// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package javareach

type pair[K, V comparable] struct {
	first  K
	second V
}

// UniqueQueue is a queue data structure that will add keys at most once in its
// lifetime. Duplicate keys are ignored when pushing them.
type UniqueQueue[K, V comparable] struct {
	seen map[K]struct{}
	q    []pair[K, V]
}

// NewQueue creates a new UniqueQueue.
func NewQueue[K, V comparable](seen map[K]struct{}) *UniqueQueue[K, V] {
	return &UniqueQueue[K, V]{
		seen: seen,
	}
}

// Push adds a key and its value to the queue. If the key is already in the queue,
// it will be ignored. It returns true if the key was added, false otherwise.
func (q *UniqueQueue[K, V]) Push(key K, value V) bool {
	if _, ok := q.seen[key]; ok {
		return false
	}
	q.seen[key] = struct{}{}
	q.q = append(q.q, pair[K, V]{key, value})

	return true
}

// Seen returns true if the key is already in the queue.
func (q *UniqueQueue[K, V]) Seen(key K) bool {
	_, ok := q.seen[key]

	return ok
}

// Pop removes the first key and value from the queue.
func (q *UniqueQueue[K, V]) Pop() (K, V) {
	item := q.q[0]
	q.q = q.q[1:]

	return item.first, item.second
}

// Empty returns true if the queue is empty.
func (q *UniqueQueue[K, V]) Empty() bool {
	return len(q.q) == 0
}
