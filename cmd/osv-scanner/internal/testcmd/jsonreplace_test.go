package testcmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tidwall/gjson"
)

func Test_repaceJSONInput(t *testing.T) {
	t.Parallel()

	matcher := func(_ gjson.Result) any {
		return "<replaced>"
	}

	tests := []struct {
		input   string
		outputs map[string]string
	}{
		{
			input:   `{}`,
			outputs: map[string]string{"": `{}`, "arr.#": `{}`},
		},
		{
			input: `{ "foo": "bar" }`,
			outputs: map[string]string{
				"does.not.exist": `{ "foo": "bar" }`,
				"foo.is.string":  `{ "foo": "bar" }`,
				"foo.#":          `{ "foo": "bar" }`,
				"#":              `{ "foo": "bar" }`,
				"foo":            `{ "foo": "<replaced>" }`,
			},
		},
		{
			input: `{ "foo": { "inner": "bar" } }`,
			outputs: map[string]string{
				"foo.inner": `{ "foo": { "inner": "<replaced>" } }`,
			},
		},
		{
			input: `{ "arr": [1, 2, 3] }`,
			outputs: map[string]string{
				"arr":   `{ "arr": "<replaced>" }`,
				"arr.1": `{ "arr": [1, "<replaced>", 3] }`,
				"arr.#": `{ "arr": ["<replaced>", "<replaced>", "<replaced>"] }`,

				"arr.#(>2)":  `{ "arr": [1, 2, "<replaced>"] }`,
				"arr.#(>1)":  `{ "arr": [1, "<replaced>", 3] }`,
				"arr.#(>1)#": `{ "arr": [1, "<replaced>", "<replaced>"] }`,
			},
		},
		{
			input: `{ "arr": [{"v": 1}, {"v": 2}, {"v": 3}] }`,
			outputs: map[string]string{
				"arr":     `{ "arr": "<replaced>" }`,
				"arr.0.v": `{ "arr": [{"v": "<replaced>"}, {"v": 2}, {"v": 3}] }`,
				"arr.1.v": `{ "arr": [{"v": 1}, {"v": "<replaced>"}, {"v": 3}] }`,
				"arr.#":   `{ "arr": ["<replaced>", "<replaced>", "<replaced>"] }`,
				"arr.#.v": `{ "arr": [{"v": "<replaced>"}, {"v": "<replaced>"}, {"v": "<replaced>"}] }`,

				"arr.#.v.#": `{ "arr": [{"v": 1}, {"v": 2}, {"v": 3}] }`,
				"arr.#.#.#": `{ "arr": [{"v": 1}, {"v": 2}, {"v": 3}] }`,
				"arr.#.#":   `{ "arr": [{"v": 1}, {"v": 2}, {"v": 3}] }`,
			},
		},
		{
			input: `{
				"arr": [
					{ "v": [{"v": 1}, {"v": 2}] },
					{ "v": [{"v": 3}, {"v": 4}] },
					{ "v": [{"v": 5}, {"v": 6}] }
				]
			}`,
			outputs: map[string]string{
				"arr": `{ "arr": "<replaced>" }`,
				"arr.0.v.0.v": `{
					"arr": [
						{ "v": [{"v": "<replaced>"}, {"v": 2}] },
						{ "v": [{"v": 3}, {"v": 4}] },
						{ "v": [{"v": 5}, {"v": 6}] }
					]
				}`,
				"arr.1.v.1.v": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": 2}] },
						{ "v": [{"v": 3}, {"v": "<replaced>"}] },
						{ "v": [{"v": 5}, {"v": 6}] }
					]
				}`,
				"arr.1.v.2.v": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": 2}] },
						{ "v": [{"v": 3}, {"v": 4}] },
						{ "v": [{"v": 5}, {"v": 6}] }
					]
				}`,

				"arr.#": `{
					"arr": [
						"<replaced>",
						"<replaced>",
						"<replaced>"
					]
				}`,
				"arr.1.v.#": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": 2}] },
						{ "v": ["<replaced>", "<replaced>"] },
						{ "v": [{"v": 5}, {"v": 6}] }
					]
				}`,
				"arr.#.v.#": `{
					"arr": [
						{ "v": ["<replaced>", "<replaced>"] },
						{ "v": ["<replaced>", "<replaced>"] },
						{ "v": ["<replaced>", "<replaced>"] }
					]
				}`,

				"arr.#.v.0.v": `{
					"arr": [
						{ "v": [{"v": "<replaced>"}, {"v": 2}] },
						{ "v": [{"v": "<replaced>"}, {"v": 4}] },
						{ "v": [{"v": "<replaced>"}, {"v": 6}] }
					]
				}`,
				"arr.#.v.1.v": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": "<replaced>"}] },
						{ "v": [{"v": 3}, {"v": "<replaced>"}] },
						{ "v": [{"v": 5}, {"v": "<replaced>"}] }
					]
				}`,
				"arr.#.v.#.v": `{
					"arr": [
						{ "v": [{"v": "<replaced>"}, {"v": "<replaced>"}] },
						{ "v": [{"v": "<replaced>"}, {"v": "<replaced>"}] },
						{ "v": [{"v": "<replaced>"}, {"v": "<replaced>"}] }
					]
				}`,
				"arr.1.v.#.v": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": 2}] },
						{ "v": [{"v": "<replaced>"}, {"v": "<replaced>"}] },
						{ "v": [{"v": 5}, {"v": 6}] }
					]
				}`,
			},
		},
		{
			input: `{
				"arr": [
					{ "v": [{"v": 1}, {"v": 2}] },
					{ "v": [{"v": 3}, {"v": 4}] },
					{ "v": [{"v": 5}, {"v": 6}] },
					{ "v": [{"v": 7}] }
				]
			}`,
			outputs: map[string]string{
				"arr.#.v.0.v": `{
					"arr": [
						{ "v": [{"v": "<replaced>"}, {"v": 2}] },
						{ "v": [{"v": "<replaced>"}, {"v": 4}] },
						{ "v": [{"v": "<replaced>"}, {"v": 6}] },
						{ "v": [{"v": "<replaced>"}] }
					]
				}`,
				"arr.#.v.1.v": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": "<replaced>"}] },
						{ "v": [{"v": 3}, {"v": "<replaced>"}] },
						{ "v": [{"v": 5}, {"v": "<replaced>"}] },
						{ "v": [{"v": 7}] }
					]
				}`,
				"arr.#.v.#.v": `{
					"arr": [
						{ "v": [{"v": "<replaced>"}, {"v": "<replaced>"}] },
						{ "v": [{"v": "<replaced>"}, {"v": "<replaced>"}] },
						{ "v": [{"v": "<replaced>"}, {"v": "<replaced>"}] },
						{ "v": [{"v": "<replaced>"}] }
					]
				}`,
				"arr.1.v.#.v": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": 2}] },
						{ "v": [{"v": "<replaced>"}, {"v": "<replaced>"}] },
						{ "v": [{"v": 5}, {"v": 6}] },
						{ "v": [{"v": 7}] }
					]
				}`,
			},
		},
		{
			input: `{
				"arr": [
					{ "v": [{"v": 1}, {"v": 2}] },
					{},
					{ "v": [{"v": 5}, {"v": 6}] },
					{ "foo": "bar" },
					{ "v": [] },
					{ "v": [{"foo": "bar"}] },
					{ "v": [{"v": 7}] }
				]
			}`,
			outputs: map[string]string{
				"arr.#.v.0.v": `{
					"arr": [
						{ "v": [{"v": "<replaced>"}, {"v": 2}] },
						{},
						{ "v": [{"v": "<replaced>"}, {"v": 6}] },
						{ "foo": "bar" },
						{ "v": [] },
						{ "v": [{"foo": "bar"}] },
						{ "v": [{"v": "<replaced>"}] }
					]
				}`,
				"arr.#.v.1.v": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": "<replaced>"}] },
						{},
						{ "v": [{"v": 5}, {"v": "<replaced>"}] },
						{ "foo": "bar" },
						{ "v": [] },
						{ "v": [{"foo": "bar"}] },
						{ "v": [{"v": 7}] }
					]
				}`,
				"arr.#.v.#.v": `{
					"arr": [
						{ "v": [{"v": "<replaced>"}, {"v": "<replaced>"}] },
						{},
						{ "v": [{"v": "<replaced>"}, {"v": "<replaced>"}] },
						{ "foo": "bar" },
						{ "v": [] },
						{ "v": [{"foo": "bar"}] },
						{ "v": [{"v": "<replaced>"}] }
					]
				}`,
				"arr.1.v.#.v": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": 2}] },
						{},
						{ "v": [{"v": 5}, {"v": 6}] },
						{ "foo": "bar" },
						{ "v": [] },
						{ "v": [{"foo": "bar"}] },
						{ "v": [{"v": 7}] }
					]
				}`,

				"arr.#": `{
					"arr": [
						"<replaced>",
						"<replaced>",
						"<replaced>",
						"<replaced>",
						"<replaced>",
						"<replaced>",
						"<replaced>"
					]
				}`,
				"arr.#.v": `{
					"arr": [
						{ "v": "<replaced>" },
						{},
						{ "v": "<replaced>" },
						{ "foo": "bar" },
						{ "v": "<replaced>" },
						{ "v": "<replaced>" },
						{ "v": "<replaced>" }
					]
				}`,
				"arr.#.v.#": `{
					"arr": [
						{ "v": ["<replaced>", "<replaced>"] },
						{},
						{ "v": ["<replaced>", "<replaced>"] },
						{ "foo": "bar" },
						{ "v": [] },
						{ "v": ["<replaced>"] },
						{ "v": ["<replaced>"] }
					]
				}`,
			},
		},
		{
			input: `{
				"arr": [
					{ "v": [{"v": 1}, {"v": 2}] },
					{},
					{ "v": [{"v": 5}, {"v": 6}] },
					{ "foo": "bar" },
					{ "v": [] },
					{ "v": [{"foo": "bar"}] },
					{ "v": [{"v": 7}] }
				]
			}`,
			outputs: map[string]string{
				"arr.#.v.#(v>=3).v": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": 2}] },
						{},
						{ "v": [{"v": "<replaced>"}, {"v": 6}] },
						{ "foo": "bar" },
						{ "v": [] },
						{ "v": [{"foo": "bar"}] },
						{ "v": [{"v": "<replaced>"}] }
					]
				}`,
				"arr.#.v.#(v>=3)#": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": 2}] },
						{},
						{ "v": ["<replaced>", "<replaced>"] },
						{ "foo": "bar" },
						{ "v": [] },
						{ "v": [{"foo": "bar"}] },
						{ "v": ["<replaced>"] }
					]
				}`,
				"arr.#.v.#(v>=3)#.v": `{
					"arr": [
						{ "v": [{"v": 1}, {"v": 2}] },
						{},
						{ "v": [{"v": "<replaced>"}, {"v": "<replaced>"}] },
						{ "foo": "bar" },
						{ "v": [] },
						{ "v": [{"foo": "bar"}] },
						{ "v": [{"v": "<replaced>"}] }
					]
				}`,
			},
		},

		{
			input: `{
				"results": [
					{},
					{
						"vulns": [
							{
								"id": "GHSA-9f46-5r25-5wfm",
								"modified": "2024-02-16T08:21:35.601880Z"
							}
						]
					},
					{},
					{},
					{}
				]
			}`,
			outputs: map[string]string{
				"results.#.vulns.#.modified": `{
					"results": [
						{},
						{
							"vulns": [
								{
									"id": "GHSA-9f46-5r25-5wfm",
									"modified": "<replaced>"
								}
							]
						},
						{},
						{},
						{}
					]
				}`,
			},
		},
	}
	for i, tt := range tests {
		paths := slices.AppendSeq(make([]string, 0, len(tt.outputs)), maps.Keys(tt.outputs))
		slices.Sort(paths)

		for _, path := range paths {
			t.Run(fmt.Sprintf("%d-%s", i, path), func(t *testing.T) {
				t.Parallel()

				got := replaceJSONInput(&testing.T{}, tt.input, path, matcher)
				if !gjson.Valid(got) {
					t.Fatalf("Output not valid: \n%s", got)
				}

				if !gjson.Valid(tt.outputs[path]) {
					t.Fatalf("Want field is not valid JSON: \n%s", tt.outputs[path])
				}

				var wantPretty bytes.Buffer
				var gotPretty bytes.Buffer

				_ = json.Indent(&wantPretty, []byte(tt.outputs[path]), "", "  ")
				_ = json.Indent(&gotPretty, []byte(got), "", "  ")

				if diff := cmp.Diff(wantPretty.String(), gotPretty.String()); diff != "" {
					t.Errorf("replaceJSONInput() diff (-want +got): %s", diff)
				}
			})
		}
	}
}

func Test_replaceJSONInput_More(t *testing.T) {
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
