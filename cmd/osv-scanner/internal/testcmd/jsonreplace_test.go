package testcmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tidwall/gjson"
)

func Test_replaceJSONInput(t *testing.T) {
	t.Parallel()

	// A nested JSON structure with arrays
	nestedArray := `{
    "items": [
      {
        "subStruct": {
          "subitems": [
            {
              "anotherSubStruct": "original value 1"
            },
            {
              "anotherSubStruct": "original value 2"
            }
          ]
        }
      },
      {
        "subStruct": {
          "subitems": [
            {
              "anotherSubStruct": "original value 3"
            },
            {
              "anotherSubStruct": "original value 4"
            }
          ]
        }
      }
    ]
  }`
	// A simple JSON structure
	simpleStruct := `{
    "test": {
      "field": "original value"
    }
  }`

	type args struct {
		jsonInput string
		path      string
		matcher   func(toReplace gjson.Result) any
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Nested json replacement",
			args: args{
				jsonInput: nestedArray,
				path:      "items.#.subStruct.subitems.#.anotherSubStruct",
				matcher: func(_ gjson.Result) any {
					return "<Any Value>"
				},
			},
			want: `{
        "items": [
          {
            "subStruct": {
              "subitems": [
                {
                  "anotherSubStruct": "<Any Value>"
                },
                {
                  "anotherSubStruct": "<Any Value>"
                }
              ]
            }
          },
          {
            "subStruct": {
              "subitems": [
                {
                  "anotherSubStruct": "<Any Value>"
                },
                {
                  "anotherSubStruct": "<Any Value>"
                }
              ]
            }
          }
        ]
      }`,
		},
		{
			name: "simple json replacement",
			args: args{
				jsonInput: simpleStruct,
				path:      "test.field",
				matcher: func(_ gjson.Result) any {
					return "<Any Value>"
				},
			},
			want: `{
        "test": {
          "field": "<Any Value>"
        }
      }`,
		},
		{
			name: "nested json array element replacement",
			args: args{
				jsonInput: nestedArray,
				path:      "items.#.subStruct.subitems.#",
				matcher: func(res gjson.Result) any {
					return res.Get("anotherSubStruct").Value()
				},
			},
			want: `{
        "items": [
          {
            "subStruct": {
              "subitems": [
                "original value 1",
                "original value 2"
              ]
            }
          },
          {
            "subStruct": {
              "subitems": [
                "original value 3",
                "original value 4"
              ]
            }
          }
        ]
      }`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := replaceJSONInput(&testing.T{}, tt.args.jsonInput, tt.args.path, tt.args.matcher)
			if !gjson.Valid(got) {
				t.Fatalf("Output not valid: \n%s", got)
			}

			if !gjson.Valid(tt.want) {
				t.Fatalf("Want field is not valid JSON: \n%s", tt.want)
			}

			var wantPretty bytes.Buffer
			var gotPretty bytes.Buffer

			_ = json.Indent(&wantPretty, []byte(tt.want), "", "\t")
			_ = json.Indent(&gotPretty, []byte(got), "", "\t")

			if diff := cmp.Diff(wantPretty.String(), gotPretty.String()); diff != "" {
				t.Errorf("replaceJSONInput() diff (-want +got): %s", diff)
			}
		})
	}
}
