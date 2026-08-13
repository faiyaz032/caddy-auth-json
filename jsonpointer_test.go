// Copyright 2026 Faiyaz Rahman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authjson

import (
	"encoding/json"
	"reflect"
	"testing"
)

// testDoc is decoded rather than built as a Go literal on purpose: only the
// JSON decoder produces the types the resolver will actually meet at runtime,
// notably float64 for every number and nil for null. A hand-written
// map[string]any would quietly substitute int and let a wrong test pass.
const testDoc = `{
	"manage": true,
	"count": 0,
	"nothing": null,
	"user": {"id": "u-42"},
	"items": ["a", "b"],
	"a.b": "dotted",
	"a": {"b": "nested"},
	"a/b": "slashed",
	"a~b": "tilded",
	"~1": "literal-tilde-one",
	"": "empty-key"
}`

func decodeTestDoc(t *testing.T) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(testDoc), &doc); err != nil {
		t.Fatalf("decoding test document: %v", err)
	}
	return doc
}

func TestJSONPointerGet(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ptr   string
		want  any
		found bool
	}{
		// resolution
		{"top level bool", "/manage", true, true},
		{"top level number is float64", "/count", float64(0), true},
		{"nested object", "/user/id", "u-42", true},
		{"array first element", "/items/0", "a", true},
		{"array last element", "/items/1", "b", true},

		// absent paths
		{"missing key", "/missing", nil, false},
		{"missing nested key", "/user/missing", nil, false},
		{"array index out of range", "/items/2", nil, false},
		{"array negative index", "/items/-1", nil, false},
		{"array non-numeric index", "/items/x", nil, false},
		{"descend into a scalar", "/manage/nope", nil, false},
		{"no leading slash", "manage", nil, false},

		// escaping: the reason JSON Pointer is used instead of dot-notation.
		// These two entries address different values through paths that
		// dot-notation would render identically.
		{"key containing a dot", "/a.b", "dotted", true},
		{"nested key of the same name", "/a/b", "nested", true},

		{"escaped slash in key", "/a~1b", "slashed", true},
		{"escaped tilde in key", "/a~0b", "tilded", true},
		{"tilde escape ordering", "/~01", "literal-tilde-one", true},
		{"lone slash is the empty key", "/", "empty-key", true},

		// null is present, which is not the same as absent; both yield a nil
		// value and only the boolean tells them apart
		{"present but null", "/nothing", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, found := jsonPointerGet(decodeTestDoc(t), tc.ptr)
			if found != tc.found {
				t.Fatalf("found = %v, want %v (value %#v)", found, tc.found, got)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestJSONPointerGetWholeDocument(t *testing.T) {
	doc := decodeTestDoc(t)

	got, found := jsonPointerGet(doc, "")
	if !found {
		t.Fatal("empty pointer should resolve to the whole document")
	}
	if !reflect.DeepEqual(got, doc) {
		t.Errorf("got %#v, want the whole document", got)
	}
}

func TestValidateJSONPointer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ptr     string
		wantErr bool
	}{
		{"simple", "/manage", false},
		{"nested", "/user/id", false},
		{"lone slash", "/", false},
		{"escaped tilde", "/a~0b", false},
		{"escaped slash", "/a~1b", false},

		{"empty", "", true},
		{"no leading slash", "manage", true},
		{"trailing tilde", "/a~", true},
		{"unknown escape", "/a~2b", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateJSONPointer(tc.ptr)
			if tc.wantErr && err == nil {
				t.Fatalf("validateJSONPointer(%q) = nil, want an error", tc.ptr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateJSONPointer(%q) = %v, want nil", tc.ptr, err)
			}
		})
	}
}
