// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"time"

	"github.com/sirupsen/logrus"

	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/lock"
	monitorConsumer "github.com/cilium/cilium/pkg/monitor/agent/consumer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// Observer is the receiver of MonitorEvents
type Observer interface {
	GetEventsChannel() chan *observerTypes.MonitorEvent
	GetLogger() logrus.FieldLogger
}

// consumer implements monitorConsumer.MonitorConsumer
type consumer struct {
	observer       Observer
	numEventsLost  uint64
	droppingEvents bool
	recoveryTimer  *time.Timer
	lostLock       lock.Mutex
}

// NewConsumer returns an initialized pointer to consumer.
func NewConsumer(observer Observer) monitorConsumer.MonitorConsumer {
	mc := &consumer{
		observer:      observer,
		numEventsLost: 0,
	}
	return mc
}

// lostLogDelay defines the delay after which the hubble events queue is
// considered "back to normal" and the lost events counter is reset.
const lostLogDelay = 5 * time.Second

// sendEventQueueLostEvents tries to send the current value of the lost events
// counter to the observer. If it succeeds to enqueue a notification, it
// resets the counter.
func (c *consumer) sendNumLostEvents() {
	c.lostLock.Lock()
	defer c.lostLock.Unlock()
	// check again, in case multiple
	// routines contended the lock
	if c.numEventsLost == 0 {
		return
	}

	numEventsLostNotification := &observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetAbsoluteNodeName(),
		Payload: &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourceEventsQueue,
			NumLostEvents: c.numEventsLost,
		},
	}
	select {
	case c.observer.GetEventsChannel() <- numEventsLostNotification:
		// We can now safely reset the counter, as at this point we have
		// successfully notified the observer about the number of events
		// that were lost since the previous LostEvent message. However, to
		// prevent noisy logs, we don't reset the flag immediately, but start
		// a timer. If we start dropping events again before it fires, the
		// timer will be stopped.
		c.observer.GetLogger().Debugf("hubble events queue received a LostEvent notification: %d messages were lost", c.numEventsLost)
		c.numEventsLost = 0
		if c.recoveryTimer == nil {
			c.recoveryTimer = time.NewTimer(lostLogDelay)
		} else {
			c.recoveryTimer.Reset(lostLogDelay)
		}
		go func() {
			select {
			case <-c.recoveryTimer.C:
				c.lostLock.Lock()
				defer c.lostLock.Unlock()
				// check again, in case multiple routines contended the lock
				if c.numEventsLost > 0 {
					return
				}
				c.observer.GetLogger().Info("hubble events queue is processing messages again")
				c.droppingEvents = false
			case <-time.After(lostLogDelay + time.Second):
				// Return if the timer was stopped before it fired
			}
		}()
	default:
		// We do not need to bump the numEventsLost counter here, as we will
		// try to send a new LostEvent notification again during the next
		// invocation of sendEvent
	}
}

// sendEvent enqueues an event in the observer. If this is not possible, it
// keeps a counter of lost events, which it will regularly try to send to the
// observer as well
func (c *consumer) sendEvent(event *observerTypes.MonitorEvent) {
	if c.numEventsLost > 0 {
		c.sendNumLostEvents()
	}
	select {
	case c.observer.GetEventsChannel() <- event:
	default:
		c.countDroppedEvent()
	}
}

// countDroppedEvent logs that the events channel is full
// and starts counting exactly how many messages it has
// lost until the consumer can recover.
func (c *consumer) countDroppedEvent() {
	c.lostLock.Lock()
	defer c.lostLock.Unlock()

	// We just started dropping events
	if !c.droppingEvents {
		c.observer.GetLogger().Warning("hubble events queue is full; dropping messages")
	}
	// We stopped dropping events for a moment, but not long enough to reset
	// the flag. Now we are dropping again, so stop the recovery timer.
	if c.droppingEvents && c.numEventsLost == 0 {
		c.recoveryTimer.Stop()
	}
	c.droppingEvents = true
	c.numEventsLost++
}

// NotifyAgentEvent implements monitorConsumer.MonitorConsumer
func (c *consumer) NotifyAgentEvent(typ int, message interface{}) {
	c.sendEvent(&observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetAbsoluteNodeName(),
		Payload: &observerTypes.AgentEvent{
			Type:    typ,
			Message: message,
		},
	})
}

// NotifyPerfEvent implements monitorConsumer.MonitorConsumer
func (c *consumer) NotifyPerfEvent(data []byte, cpu int) {
	c.sendEvent(&observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetAbsoluteNodeName(),
		Payload: &observerTypes.PerfEvent{
			Data: data,
			CPU:  cpu,
		},
	})
}

// NotifyPerfEventLost implements monitorConsumer.MonitorConsumer
func (c *consumer) NotifyPerfEventLost(numLostEvents uint64, cpu int) {
	c.sendEvent(&observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetAbsoluteNodeName(),
		Payload: &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourcePerfRingBuffer,
			NumLostEvents: numLostEvents,
			CPU:           cpu,
		},
	})
}
