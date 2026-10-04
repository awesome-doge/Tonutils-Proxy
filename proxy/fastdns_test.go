package proxy

import (
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/ton"
)

func blk(seq uint32) *ton.BlockIDExt { return &ton.BlockIDExt{Workchain: -1, SeqNo: seq} }

// A lookup asks at a block that has settled, not at the newest one: on 2026-10-04 the public
// liteservers answered 30% of lookups at the newest block and 132 of 132 at one 90 s old.
func TestALookupAsksAtASettledBlock(t *testing.T) {
	var h blockHistory
	t0 := time.Unix(1_800_000_000, 0)
	// one block every 3 s for five minutes, as refreshBlocks files them
	for i := 0; i <= 100; i++ {
		h.add(blk(uint32(1000+i*7)), t0.Add(time.Duration(i)*3*time.Second))
	}
	now := t0.Add(300 * time.Second)

	for attempt, wantAge := range []time.Duration{90 * time.Second, 180 * time.Second, 300 * time.Second} {
		got := h.pick(settledAges[attempt], now)
		want := uint32(1000 + int((300*time.Second-wantAge)/(3*time.Second))*7)
		if got == nil || got.SeqNo != want {
			t.Fatalf("attempt %d: got %v, want the block that is %s old (seqno %d)", attempt, got, wantAge, want)
		}
	}
	if newest := h.pick(0, now); newest.SeqNo != 1700 {
		t.Fatalf("age 0 is the newest block, got %d", newest.SeqNo)
	}
}

func TestRightAfterAStartTheOldestBlockIsUsed(t *testing.T) {
	var h blockHistory
	t0 := time.Unix(1_800_000_000, 0)
	if h.pick(settledAges[0], t0) != nil {
		t.Fatal("no block yet: the standard resolver has to be used")
	}
	h.add(blk(5000), t0)
	h.add(blk(5007), t0.Add(3*time.Second))
	if got := h.pick(settledAges[0], t0.Add(4*time.Second)); got.SeqNo != 5000 {
		t.Fatalf("nothing is 90 s old yet: the oldest block, got %d", got.SeqNo)
	}

	// the blocks looked up at the start are filed in front, oldest first, under their age
	h.seed([]cachedBlock{
		{b: blk(4250), at: t0.Add(-300 * time.Second)},
		{b: blk(4500), at: t0.Add(-200 * time.Second)},
		{b: blk(4750), at: t0.Add(-100 * time.Second)},
	})
	now := t0.Add(4 * time.Second)
	for attempt, want := range []uint32{4750, 4500, 4250} {
		if got := h.pick(settledAges[attempt], now); got.SeqNo != want {
			t.Fatalf("attempt %d after seeding: got %d, want %d", attempt, got.SeqNo, want)
		}
	}
	// a seed that is not older than what is there is not filed
	h.seed([]cachedBlock{{b: blk(6000), at: t0.Add(-50 * time.Second)}})
	if got := h.pick(settledAges[0], now); got.SeqNo != 4750 {
		t.Fatalf("a newer block must not be filed as an old one, got %d", got.SeqNo)
	}
}

func TestAnAnswerFromALaggingLiteserverIsNotFiled(t *testing.T) {
	var h blockHistory
	t0 := time.Unix(1_800_000_000, 0)
	h.add(blk(900), t0)
	h.add(blk(880), t0.Add(3*time.Second)) // a liteserver that is behind
	h.add(blk(900), t0.Add(6*time.Second)) // the same block again
	if len(h.blocks) != 1 {
		t.Fatalf("want 1 block filed, got %d", len(h.blocks))
	}
}

func TestOldBlocksAreDroppedAndAStalledRefreshIsNoticed(t *testing.T) {
	var h blockHistory
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i <= 400; i++ { // twenty minutes
		h.add(blk(uint32(100+i)), t0.Add(time.Duration(i)*3*time.Second))
	}
	last := t0.Add(1200 * time.Second)
	if oldest := h.blocks[0]; last.Sub(oldest.at) > blockKeepFor+3*time.Second {
		t.Fatalf("a block %s old is still kept", last.Sub(oldest.at))
	}
	if h.pick(settledAges[2], last) == nil {
		t.Fatal("a refresh that works always has a settled block")
	}
	// no new block for longer than blockKeepFor: the refresh has stopped, do not ask at a relic
	if got := h.pick(settledAges[0], last.Add(blockKeepFor+time.Second)); got != nil {
		t.Fatalf("stalled refresh: want nil, got block %d", got.SeqNo)
	}
}
