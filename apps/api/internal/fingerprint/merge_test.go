package fingerprint

import (
	"reflect"
	"testing"
)

func TestMergeShallow(t *testing.T) {
	client := Components{"a": 1, "b": Components{"x": 1}}
	server := Components{"b": Components{"y": 2}, "c": 3}
	got := Merge(client, server)
	want := Components{"a": 1, "b": Components{"y": 2}, "c": 3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	if _, ok := client["c"]; ok {
		t.Error("client mutated")
	}
}
