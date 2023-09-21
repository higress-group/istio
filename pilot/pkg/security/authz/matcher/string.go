// Copyright Istio Authors
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

package matcher

import (
	"fmt"
	"strings"

	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"

	authz "istio.io/api/security/v1beta1"
)

// StringMatcher creates a string matcher for v.
func StringMatcher(v string) *matcher.StringMatcher {
	return StringMatcherWithPrefix(v, "")
}

// StringMatcherRegex creates a regex string matcher for regex.
func StringMatcherRegex(regex string) *matcher.StringMatcher {
	return &matcher.StringMatcher{
		MatchPattern: &matcher.StringMatcher_SafeRegex{
			SafeRegex: &matcher.RegexMatcher{
				Regex: regex,
			},
		},
	}
}

// StringMatcherWithPrefix creates a string matcher for v with the extra prefix inserted to the
// created string matcher, note the prefix is ignored if v is wildcard ("*").
// The wildcard "*" will be generated as ".+" instead of ".*".
func StringMatcherWithPrefix(v, prefix string) *matcher.StringMatcher {
	switch {
	// Check if v is "*" first to make sure we won't generate an empty prefix/suffix StringMatcher,
	// the Envoy StringMatcher doesn't allow empty prefix/suffix.
	case v == "*":
		return StringMatcherRegex(".+")
	case strings.HasPrefix(v, "*"):
		if prefix == "" {
			return &matcher.StringMatcher{
				MatchPattern: &matcher.StringMatcher_Suffix{
					Suffix: strings.TrimPrefix(v, "*"),
				},
			}
		}
		return StringMatcherRegex(prefix + ".*" + strings.TrimPrefix(v, "*"))
	case strings.HasSuffix(v, "*"):
		return &matcher.StringMatcher{
			MatchPattern: &matcher.StringMatcher_Prefix{
				Prefix: prefix + strings.TrimSuffix(v, "*"),
			},
		}
	default:
		return &matcher.StringMatcher{
			MatchPattern: &matcher.StringMatcher_Exact{
				Exact: prefix + v,
			},
		}
	}
}

// Added by ingress
const (
	Exact  = "exact"
	Prefix = "prefix"
	Regex  = "regex"
)

// ExtensionStringMatcher creates a string matcher for v.
func ExtensionStringMatcher(v string) *matcher.StringMatcher {
	parts := strings.SplitN(v, "|", 2)
	switch parts[0] {
	case Prefix:
		return &matcher.StringMatcher{
			MatchPattern: &matcher.StringMatcher_Prefix{
				Prefix: parts[1],
			},
		}
	case Regex:
		return &matcher.StringMatcher{
			MatchPattern: &matcher.StringMatcher_SafeRegex{
				SafeRegex: &matcher.RegexMatcher{
					EngineType: &matcher.RegexMatcher_GoogleRe2{
						GoogleRe2: &matcher.RegexMatcher_GoogleRE2{},
					},
					Regex: parts[1],
				},
			},
		}
	default:
		return &matcher.StringMatcher{
			MatchPattern: &matcher.StringMatcher_Exact{
				Exact: parts[1],
			},
		}
	}
}

// StringMatchToString convert struct string match to string
// Exact: /app/test -> exact|/app/test
// Prefix: /app -> prefix|/app
// Regex: /app/(.*)/test -> regex|/app/(.*)/test
func StringMatchToString(stringMatch []*authz.StringMatch) []string {
	var result []string
	for _, match := range stringMatch {
		switch match.MatchType.(type) {
		case *authz.StringMatch_Exact:
			result = append(result, fmt.Sprintf("%s|%s", Exact, match.GetExact()))
		case *authz.StringMatch_Prefix:
			result = append(result, fmt.Sprintf("%s|%s", Prefix, strings.TrimSuffix(match.GetPrefix(), "*")))
		case *authz.StringMatch_Regex:
			result = append(result, fmt.Sprintf("%s|%s", Regex, match.GetRegex()))
		}
	}
	return result
}
