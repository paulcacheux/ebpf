package ringbuf

import (
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

type ringbufEventRing struct {
	prod []byte
	cons []byte
	*ringReader
}

func newRingBufEventRing(mapFD, size int) (*ringbufEventRing, error) {
	cons, err := unix.Mmap(mapFD, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("can't mmap consumer page: %w", err)
	}

	prod, err := unix.Mmap(mapFD, (int64)(os.Getpagesize()), os.Getpagesize()+2*size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(cons)
		return nil, fmt.Errorf("can't mmap data pages: %w", err)
	}

	cons_pos := (*uint64)(unsafe.Pointer(&cons[0]))
	prod_pos := (*uint64)(unsafe.Pointer(&prod[0]))

	ring := &ringbufEventRing{
		prod:       prod,
		cons:       cons,
		ringReader: newRingReader(cons_pos, prod_pos, prod[os.Getpagesize():]),
	}
	runtime.SetFinalizer(ring, (*ringbufEventRing).Close)

	return ring, nil
}

func (ring *ringbufEventRing) Close() {
	runtime.SetFinalizer(ring, nil)

	_ = unix.Munmap(ring.prod)
	_ = unix.Munmap(ring.cons)

	ring.prod = nil
	ring.cons = nil
}

type ringReader struct {
	// These point into mmap'ed memory and must be accessed atomically.
	prod_pos, cons_pos *uint64
	mask               uint64
	ring               []byte
}

func newRingReader(cons_ptr, prod_ptr *uint64, ring []byte) *ringReader {
	return &ringReader{
		prod_pos: prod_ptr,
		cons_pos: cons_ptr,
		// cap is always a power of two
		mask: uint64(cap(ring)/2 - 1),
		ring: ring,
	}
}

func (rr *ringReader) isEmpty() bool {
	cons := atomic.LoadUint64(rr.cons_pos)
	prod := atomic.LoadUint64(rr.prod_pos)

	return prod == cons
}

func (rr *ringReader) size() int {
	return cap(rr.ring)
}

func (rr *ringReader) remaining() int {
	cons := atomic.LoadUint64(rr.cons_pos)
	prod := atomic.LoadUint64(rr.prod_pos)

	return int((prod - cons) & rr.mask)
}

func (rr *ringReader) readRecord(callback func(sample []byte)) error {
	cons := atomic.LoadUint64(rr.cons_pos)
	pos := atomic.LoadUint64(rr.prod_pos)

	if pos <= cons {
		return errEOR
	}

	len := atomic.LoadUint32((*uint32)((unsafe.Pointer)(&rr.ring[cons&rr.mask])))

	if len&unix.BPF_RINGBUF_BUSY_BIT != 0 {
		return errBusy
	}

	cons += unix.BPF_RINGBUF_HDR_SZ

	// clear busy and discard bits
	sample_len := len & ^uint32(unix.BPF_RINGBUF_BUSY_BIT|unix.BPF_RINGBUF_DISCARD_BIT)
	aligned_len := uint64(internal.Align(sample_len, 8))

	if len&unix.BPF_RINGBUF_DISCARD_BIT != 0 {
		cons += aligned_len
		atomic.StoreUint64(rr.cons_pos, cons)
		return errDiscard
	}

	start := cons & rr.mask
	end := start + uint64(sample_len)
	sample := rr.ring[start:end]
	callback(sample)

	cons += aligned_len
	atomic.StoreUint64(rr.cons_pos, cons)

	return nil
}
