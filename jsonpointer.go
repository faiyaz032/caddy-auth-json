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
	"fmt"
	"strconv"
	"strings"
)

// jsonPointerGet resolves an RFC 6901 JSON Pointer against a decoded JSON
// document. It reports false if any token along the path is missing, so
// callers can distinguish "absent" from "present and false/null".
//
// JSON Pointer is used instead of dot-notation because object keys are
// allowed to contain dots: the document {"a.b": 1, "a": {"b": 2}} is
// perfectly legal, and "a.b" cannot address both.
func jsonPointerGet(doc any, ptr string) (any, bool) {
	if ptr == "" {
		return doc, true
	}
	if !strings.HasPrefix(ptr, "/") {
		return nil, false
	}

	cur := doc
	for _, tok := range strings.Split(ptr[1:], "/") {
		tok = unescapePointerToken(tok)

		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[tok]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			// array indices must be canonical decimal, per RFC 6901
			idx, err := strconv.Atoi(tok)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			// tried to descend into a scalar
			return nil, false
		}
	}
	return cur, true
}

// unescapePointerToken reverses RFC 6901 escaping. Order matters: ~1 must be
// decoded before ~0, otherwise "~01" would wrongly become "/" instead of "~1".
func unescapePointerToken(tok string) string {
	tok = strings.ReplaceAll(tok, "~1", "/")
	return strings.ReplaceAll(tok, "~0", "~")
}

// validateJSONPointer checks a pointer is well-formed so that config errors
// surface at provision time rather than silently denying every request.
func validateJSONPointer(ptr string) error {
	if ptr == "" {
		return fmt.Errorf("JSON pointer must not be empty")
	}
	if !strings.HasPrefix(ptr, "/") {
		return fmt.Errorf("JSON pointer %q must begin with '/'", ptr)
	}
	for _, tok := range strings.Split(ptr[1:], "/") {
		for i := 0; i < len(tok); i++ {
			if tok[i] != '~' {
				continue
			}
			if i+1 >= len(tok) || (tok[i+1] != '0' && tok[i+1] != '1') {
				return fmt.Errorf("JSON pointer %q has an invalid escape sequence; '~' must be followed by '0' or '1'", ptr)
			}
			i++
		}
	}
	return nil
}
