package ebpf

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestMapInfoFromProc(t *testing.T) {
	hash, err := NewMap(&MapSpec{
		Name:       "testing",
		Type:       Hash,
		KeySize:    4,
		ValueSize:  5,
		MaxEntries: 2,
		Flags:      sys.BPF_F_NO_PREALLOC,
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer hash.Close()

	info, err := newMapInfoFromProc(hash.fd)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't get map info:", err)
	}

	if info.Type != Hash {
		t.Error("Expected Hash, got", info.Type)
	}

	if info.KeySize != 4 {
		t.Error("Expected KeySize of 4, got", info.KeySize)
	}

	if info.ValueSize != 5 {
		t.Error("Expected ValueSize of 5, got", info.ValueSize)
	}

	if info.MaxEntries != 2 {
		t.Error("Expected MaxEntries of 2, got", info.MaxEntries)
	}

	if info.Flags != sys.BPF_F_NO_PREALLOC {
		t.Errorf("Expected Flags to be %d, got %d", sys.BPF_F_NO_PREALLOC, info.Flags)
	}

	if info.Name != "" && info.Name != "testing" {
		t.Error("Expected name to be testing, got", info.Name)
	}

	if _, ok := info.ID(); ok {
		t.Error("Expected ID to not be available")
	}

	nested, err := NewMap(&MapSpec{
		Type:       ArrayOfMaps,
		KeySize:    4,
		MaxEntries: 2,
		InnerMap: &MapSpec{
			Type:       Array,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 2,
		},
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer nested.Close()

	_, err = newMapInfoFromProc(nested.fd)
	if err != nil {
		t.Fatal("Can't get nested map info from /proc:", err)
	}
}

func TestProgramInfo(t *testing.T) {
	prog := mustSocketFilter(t)

	for name, fn := range map[string]func(*sys.FD) (*ProgramInfo, error){
		"generic": newProgramInfoFromFd,
		"proc":    newProgramInfoFromProc,
	} {
		t.Run(name, func(t *testing.T) {
			info, err := fn(prog.fd)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal("Can't get program info:", err)
			}

			if info.Type != SocketFilter {
				t.Error("Expected Type to be SocketFilter, got", info.Type)
			}

			if info.Name != "" && info.Name != "test" {
				t.Error("Expected Name to be test, got", info.Name)
			}

			if want := "d7edec644f05498d"; info.Tag != want {
				t.Errorf("Expected Tag to be %s, got %s", want, info.Tag)
			}

			if id, ok := info.ID(); ok && id == 0 {
				t.Error("Expected a valid ID:", id)
			} else if name == "proc" && ok {
				t.Error("Expected ID to not be available")
			}

			if name == "proc" {
				_, err := info.JitedSize()
				qt.Assert(t, qt.IsNotNil(err))

				_, err = info.TranslatedSize()
				qt.Assert(t, qt.IsNotNil(err))

				_, ok := info.CreatedByUID()
				qt.Assert(t, qt.IsFalse(ok))

				_, ok = info.LoadTime()
				qt.Assert(t, qt.IsFalse(ok))

				_, ok = info.VerifiedInstructions()
				qt.Assert(t, qt.IsFalse(ok))
			} else {
				if jitedSize, err := info.JitedSize(); testutils.IsKernelLessThan(t, "4.13") {
					qt.Assert(t, qt.IsNotNil(err))
				} else {
					qt.Assert(t, qt.IsNil(err))
					qt.Assert(t, qt.IsTrue(jitedSize > 0))
				}

				if xlatedSize, err := info.TranslatedSize(); testutils.IsKernelLessThan(t, "4.13") {
					qt.Assert(t, qt.IsNotNil(err))
				} else {
					qt.Assert(t, qt.IsNil(err))
					qt.Assert(t, qt.IsTrue(xlatedSize > 0))
				}

				if uid, ok := info.CreatedByUID(); testutils.IsKernelLessThan(t, "4.15") {
					qt.Assert(t, qt.IsFalse(ok))
				} else {
					qt.Assert(t, qt.IsTrue(ok))
					qt.Assert(t, qt.Equals(uid, uint32(os.Getuid())))
				}

				if loadTime, ok := info.LoadTime(); testutils.IsKernelLessThan(t, "4.15") {
					qt.Assert(t, qt.IsFalse(ok))
				} else {
					qt.Assert(t, qt.IsTrue(ok))
					qt.Assert(t, qt.IsTrue(loadTime > 0))
				}

				if verifiedInsns, ok := info.VerifiedInstructions(); testutils.IsKernelLessThan(t, "5.16") {
					qt.Assert(t, qt.IsFalse(ok))
				} else {
					qt.Assert(t, qt.IsTrue(ok))
					qt.Assert(t, qt.IsTrue(verifiedInsns > 0))
				}
			}
		})
	}
}

func TestProgramInfoMapIDs(t *testing.T) {
	arr, err := NewMap(&MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	qt.Assert(t, qt.IsNil(err))
	defer arr.Close()

	prog, err := NewProgram(&ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R0, arr.FD()),
			asm.LoadImm(asm.R0, 2, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	qt.Assert(t, qt.IsNil(err))
	defer prog.Close()

	info, err := prog.Info()
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	ids, ok := info.MapIDs()
	switch {
	case testutils.IsKernelLessThan(t, "4.15"):
		qt.Assert(t, qt.IsFalse(ok))
		qt.Assert(t, qt.HasLen(ids, 0))

	default:
		qt.Assert(t, qt.IsTrue(ok))

		mapInfo, err := arr.Info()
		qt.Assert(t, qt.IsNil(err))

		mapID, ok := mapInfo.ID()
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.ContentEquals(ids, []MapID{mapID}))
	}
}

func TestProgramInfoMapIDsNoMaps(t *testing.T) {
	prog, err := NewProgram(&ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	qt.Assert(t, qt.IsNil(err))
	defer prog.Close()

	info, err := prog.Info()
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	ids, ok := info.MapIDs()
	switch {
	case testutils.IsKernelLessThan(t, "4.15"):
		qt.Assert(t, qt.IsFalse(ok))
		qt.Assert(t, qt.HasLen(ids, 0))

	default:
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.HasLen(ids, 0))
	}
}

func TestScanFdInfoReader(t *testing.T) {
	tests := []struct {
		fields map[string]interface{}
		valid  bool
	}{
		{nil, true},
		{map[string]interface{}{"foo": new(string)}, true},
		{map[string]interface{}{"zap": new(string)}, false},
		{map[string]interface{}{"foo": new(int)}, false},
	}

	for _, test := range tests {
		err := scanFdInfoReader(strings.NewReader("foo:\tbar\n"), test.fields)
		if test.valid {
			if err != nil {
				t.Errorf("fields %v returns an error: %s", test.fields, err)
			}
		} else {
			if err == nil {
				t.Errorf("fields %v doesn't return an error", test.fields)
			}
		}
	}
}

// TestStats loads a BPF program once and executes back-to-back test runs
// of the program. See testStats for details.
func TestStats(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF_ENABLE_STATS")

	prog := mustSocketFilter(t)

	pi, err := prog.Info()
	if err != nil {
		t.Errorf("failed to get ProgramInfo: %v", err)
	}

	rc, ok := pi.RunCount()
	if !ok {
		t.Errorf("expected run count info to be available")
	}
	if rc != 0 {
		t.Errorf("expected a run count of 0 but got %d", rc)
	}

	rt, ok := pi.Runtime()
	if !ok {
		t.Errorf("expected runtime info to be available")
	}
	if rt != 0 {
		t.Errorf("expected a runtime of 0ns but got %v", rt)
	}

	rm, ok := pi.RecursionMisses()
	if !ok {
		t.Errorf("expected recursion misses info to be available")
	}
	if rm != 0 {
		t.Errorf("expected a recursion misses of 0 but got %v", rm)
	}

	if err := testStats(prog); err != nil {
		t.Error(err)
	}
}

// BenchmarkStats is a benchmark of TestStats. See testStats for details.
func BenchmarkStats(b *testing.B) {
	testutils.SkipOnOldKernel(b, "5.8", "BPF_ENABLE_STATS")

	prog := mustSocketFilter(b)

	for n := 0; n < b.N; n++ {
		if err := testStats(prog); err != nil {
			b.Fatal(fmt.Errorf("iter %d: %w", n, err))
		}
	}
}

// testStats implements the behaviour under test for TestStats
// and BenchmarkStats. First, a test run is executed with runtime statistics
// enabled, followed by another with runtime stats disabled. Counters are only
// expected to increase on the runs where runtime stats are enabled.
//
// Due to runtime behaviour on Go 1.14 and higher, the syscall backing
// (*Program).Test() could be invoked multiple times for each call to Test(),
// resulting in RunCount incrementing by more than one. Expecting RunCount to
// be of a specific value after a call to Test() is therefore not possible.
// See https://golang.org/doc/go1.14#runtime for more details.
func testStats(prog *Program) error {
	in := internal.EmptyBPFContext

	stats, err := EnableStats(uint32(sys.BPF_STATS_RUN_TIME))
	if err != nil {
		return fmt.Errorf("failed to enable stats: %v", err)
	}
	defer stats.Close()

	// Program execution with runtime statistics enabled.
	// Should increase both runtime and run counter.
	if _, _, err := prog.Test(in); err != nil {
		return fmt.Errorf("failed to trigger program: %v", err)
	}

	pi, err := prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get ProgramInfo: %v", err)
	}

	rc, ok := pi.RunCount()
	if !ok {
		return errors.New("expected run count info to be available")
	}
	if rc < 1 {
		return fmt.Errorf("expected a run count of at least 1 but got %d", rc)
	}
	// Store the run count for the next invocation.
	lc := rc

	rt, ok := pi.Runtime()
	if !ok {
		return errors.New("expected runtime info to be available")
	}
	if rt == 0 {
		return errors.New("expected a runtime other than 0ns")
	}
	// Store the runtime value for the next invocation.
	lt := rt

	if err := stats.Close(); err != nil {
		return fmt.Errorf("failed to disable statistics: %v", err)
	}

	// Second program execution, with runtime statistics gathering disabled.
	// Total runtime and run counters are not expected to increase.
	if _, _, err := prog.Test(in); err != nil {
		return fmt.Errorf("failed to trigger program: %v", err)
	}

	pi, err = prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get ProgramInfo: %v", err)
	}

	rc, ok = pi.RunCount()
	if !ok {
		return errors.New("expected run count info to be available")
	}
	if rc != lc {
		return fmt.Errorf("run count unexpectedly increased over previous value (current: %v, prev: %v)", rc, lc)
	}

	rt, ok = pi.Runtime()
	if !ok {
		return errors.New("expected runtime info to be available")
	}
	if rt != lt {
		return fmt.Errorf("runtime unexpectedly increased over the previous value (current: %v, prev: %v)", rt, lt)
	}

	return nil
}

func TestHaveProgramInfoMapIDs(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgramInfoMapIDs)
}

func TestProgInfoExtBTF(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.0", "Program BTF (func/line_info)")

	spec, err := LoadCollectionSpec(testutils.NativeFile(t, "testdata/loader-%s.elf"))
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		Main *Program `ebpf:"xdp_prog"`
	}

	err = spec.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Main.Close()

	info, err := obj.Main.Info()
	if err != nil {
		t.Fatal(err)
	}

	inst, err := info.Instructions()
	if err != nil {
		t.Fatal(err)
	}

	expectedLineInfoCount := 28
	expectedFuncInfo := map[string]bool{
		"xdp_prog":   false,
		"static_fn":  false,
		"global_fn2": false,
		"global_fn3": false,
	}

	lineInfoCount := 0

	for _, ins := range inst {
		if ins.Source() != nil {
			lineInfoCount++
		}

		fn := btf.FuncMetadata(&ins)
		if fn != nil {
			expectedFuncInfo[fn.Name] = true
		}
	}

	if lineInfoCount != expectedLineInfoCount {
		t.Errorf("expected %d line info entries, got %d", expectedLineInfoCount, lineInfoCount)
	}

	for fn, found := range expectedFuncInfo {
		if !found {
			t.Errorf("func %q not found", fn)
		}
	}
}

func TestInfoExportedFields(t *testing.T) {
	// It is highly unlikely that you should be adjusting the asserts below.
	// See the comment at the top of info.go for more information.

	var names []string
	for _, field := range reflect.VisibleFields(reflect.TypeOf(MapInfo{})) {
		if field.IsExported() {
			names = append(names, field.Name)
		}
	}
	qt.Assert(t, qt.ContentEquals(names, []string{
		"Type",
		"KeySize",
		"ValueSize",
		"MaxEntries",
		"Flags",
		"Name",
	}))

	names = nil
	for _, field := range reflect.VisibleFields(reflect.TypeOf(ProgramInfo{})) {
		if field.IsExported() {
			names = append(names, field.Name)
		}
	}
	qt.Assert(t, qt.ContentEquals(names, []string{
		"Type",
		"Tag",
		"Name",
	}))
}
