package supervisor

import "sync"

// pauseState is a broadcast switch: many goroutines wait on it, and one flip
// releases all of them.
//
// It exists so that stopping the stack does not have to mean stopping the
// daemon. The menu bar runs as the user and cannot unload a root launchd job,
// so if "stop" meant "exit", the only way back would be a password prompt. A
// paused daemon keeps answering, which is what lets a menu bar item turn the
// whole thing off and on again.
//
// Two channels rather than one, each closed in the state it names, because a
// closed channel is the only signal every waiter sees.
type pauseState struct {
	mu      sync.Mutex
	paused  bool
	pausedC chan struct{}
	runC    chan struct{}
}

func newPauseState() *pauseState {
	p := &pauseState{
		pausedC: make(chan struct{}),
		runC:    make(chan struct{}),
	}
	close(p.runC) // start running
	return p
}

func (p *pauseState) Paused() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.paused
}

// WhilePaused is closed for as long as the stack is paused. Wait on it to
// block until a resume.
func (p *pauseState) WhilePaused() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pausedC
}

// WhileRunning is closed for as long as the stack is running. Select on it to
// be interrupted the moment a pause is asked for.
func (p *pauseState) WhileRunning() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.runC
}

// Set moves to the requested state and reports whether anything changed.
func (p *pauseState) Set(paused bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.paused == paused {
		return false
	}
	p.paused = paused

	if paused {
		p.runC = make(chan struct{})
		close(p.pausedC)
		return true
	}

	p.pausedC = make(chan struct{})
	close(p.runC)
	return true
}
