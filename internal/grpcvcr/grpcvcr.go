// Package grpcvcr provides a VCR-like recording and replaying library for gRPC unary calls.
package grpcvcr

import (
	"context"
	"errors"
	"fmt"

	"os"
	"path/filepath"
	"sync"

	"go.yaml.in/yaml/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"encoding/json"
	"github.com/google/go-cmp/cmp"
	"slices"
	"strings"
)

// Mode defines the VCR operational mode.
type Mode int

const (
	// ModeRecordOnly records interactions and does not replay.
	ModeRecordOnly Mode = iota
	// ModeReplayOnly replays interactions and errors if missing.
	ModeReplayOnly
	// ModeReplayWithNewEpisodes replays interactions, and records new ones if missing.
	ModeReplayWithNewEpisodes
	// ModePassthrough disables VCR and calls the real service.
	ModePassthrough
)

// StatusError represents a recorded gRPC status error.
type StatusError struct {
	Code    uint32 `yaml:"code"`
	Message string `yaml:"message"`
}

// Interaction represents a single gRPC call record.
type Interaction struct {
	Method   string       `yaml:"method"`
	Request  string       `yaml:"request"`            // JSON serialized proto
	Response string       `yaml:"response,omitempty"` // JSON serialized proto (empty if error)
	Error    *StatusError `yaml:"error,omitempty"`
}

// Cassette holds the recorded interactions.
type Cassette struct {
	Interactions []Interaction `yaml:"interactions"`
}

// Matcher defines the function signature for matching a request to a recorded interaction.
type Matcher func(method string, req proto.Message, recordedReqJSON string) bool

// DefaultMatcher matches requests by deserializing them to maps/slices, normalizing them,
// recursively sorting all slices (arrays) to make comparison order-independent,
// and finally comparing them using cmp.Equal.
func DefaultMatcher(_ string, req proto.Message, recordedReqJSON string) bool {
	clone := proto.Clone(req)
	proto.Reset(clone)
	if err := protojson.Unmarshal([]byte(recordedReqJSON), clone); err != nil {
		return false
	}

	reqJSON, err := marshalOptions.Marshal(req)
	if err != nil {
		return false
	}
	cloneJSON, err := marshalOptions.Marshal(clone)
	if err != nil {
		return false
	}

	var gotVal, wantVal any
	if err := json.Unmarshal(reqJSON, &gotVal); err != nil {
		return false
	}
	if err := json.Unmarshal(cloneJSON, &wantVal); err != nil {
		return false
	}

	return cmp.Equal(sortSlices(gotVal), sortSlices(wantVal))
}

func sortSlices(val any) any {
	switch v := val.(type) {
	case map[string]any:
		res := make(map[string]any, len(v))
		for k, val := range v {
			res[k] = sortSlices(val)
		}
		return res
	case []any:
		res := make([]any, len(v))
		for i, val := range v {
			res[i] = sortSlices(val)
		}
		type sortedElem struct {
			original any
			jsonStr  string
		}
		elems := make([]sortedElem, len(res))
		for i, el := range res {
			b, _ := json.Marshal(el)
			elems[i] = sortedElem{original: el, jsonStr: string(b)}
		}
		slices.SortFunc(elems, func(a, b sortedElem) int {
			return strings.Compare(a.jsonStr, b.jsonStr)
		})
		sortedRes := make([]any, len(res))
		for i, el := range elems {
			sortedRes[i] = el.original
		}
		return sortedRes
	default:
		return val
	}
}

var marshalOptions = protojson.MarshalOptions{
	Multiline: true,
	Indent:    "  ",
}

// Recorder manages the VCR recording and replaying.
type Recorder struct {
	mode         Mode
	testName     string
	cassettePath string
	cassette     *Cassette
	matcher      Matcher
	mu           sync.Mutex
	// OnMiss is called when an interaction is not found during replay.
	// This can be used to log detailed mismatches in tests.
	OnMiss func(method string, req proto.Message, cassette *Cassette)
}

// NewRecorder creates and initializes a new Recorder.
func NewRecorder(cassettePath string, mode Mode, testName string) (*Recorder, error) {
	r := &Recorder{
		mode:         mode,
		testName:     testName,
		cassettePath: cassettePath,
		matcher:      DefaultMatcher,
		cassette:     &Cassette{},
	}

	if mode == ModePassthrough {
		return r, nil
	}

	if mode == ModeRecordOnly {
		// Erase existing cassette file to start fresh
		_ = os.Remove(r.cassettePath)
		return r, nil
	}

	if err := r.loadCassette(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to load cassette: %w", err)
		}
	}

	return r, nil
}

func (r *Recorder) loadCassette() error {
	data, err := os.ReadFile(r.cassettePath)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, r.cassette)
}

func (r *Recorder) saveCassette() error {
	if err := os.MkdirAll(filepath.Dir(r.cassettePath), 0755); err != nil {
		return err
	}

	// Sort interactions to ensure deterministic output order in the cassette file,
	// preventing noisy git diffs when cassettes are re-recorded.
	slices.SortFunc(r.cassette.Interactions, func(a, b Interaction) int {
		if c := strings.Compare(a.Method, b.Method); c != 0 {
			return c
		}
		if c := strings.Compare(a.Request, b.Request); c != 0 {
			return c
		}
		return strings.Compare(a.Response, b.Response)
	})

	data, err := yaml.Marshal(r.cassette)
	if err != nil {
		return err
	}

	return os.WriteFile(r.cassettePath, data, 0600)
}

func (r *Recorder) findInteraction(method string, req proto.Message) (*Interaction, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, inter := range r.cassette.Interactions {
		if inter.Method == method {
			if r.matcher(method, req, inter.Request) {
				return &inter, true
			}
		}
	}

	return nil, false
}

// Intercept intercepts a gRPC unary call, replaying or recording it based on the mode.
func (r *Recorder) Intercept(_ context.Context, method string, args, reply any, invokeReal func() error) error {
	if r.mode == ModePassthrough {
		return invokeReal()
	}

	reqProto, ok := args.(proto.Message)
	if !ok {
		return errors.New("args does not implement proto.Message")
	}

	respProto, ok := reply.(proto.Message)
	if !ok {
		return errors.New("reply does not implement proto.Message")
	}

	reqJSON, err := marshalOptions.Marshal(reqProto)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Replay attempt
	if r.mode == ModeReplayOnly || r.mode == ModeReplayWithNewEpisodes {
		matched, found := r.findInteraction(method, reqProto)
		if found {
			if matched.Error != nil {
				return status.Error(codes.Code(matched.Error.Code), matched.Error.Message)
			}

			return protojson.Unmarshal([]byte(matched.Response), respProto)
		}
		if r.mode == ModeReplayOnly {
			if r.OnMiss != nil {
				r.OnMiss(method, reqProto, r.cassette)
			}
			return status.Errorf(codes.NotFound, "gRPC VCR: interaction not found for method %s (Test: %s)", method, r.testName)
		}
	}

	// Record Mode / Miss in ReplayWithNewEpisodes
	err = invokeReal()

	cleanedReq, cleanErr := cleanJSON(string(reqJSON))
	if cleanErr != nil {
		return fmt.Errorf("failed to clean request JSON: %w", cleanErr)
	}

	var interaction Interaction
	interaction.Method = method
	interaction.Request = cleanedReq

	if err != nil {
		if st, ok := status.FromError(err); ok {
			interaction.Error = &StatusError{
				Code:    uint32(st.Code()),
				Message: st.Message(),
			}
		} else {
			return err // Only record gRPC status errors
		}
	} else {
		respJSON, err := marshalOptions.Marshal(respProto)
		if err != nil {
			return fmt.Errorf("failed to marshal response: %w", err)
		}
		cleanedResp, cleanErr := cleanJSON(string(respJSON))
		if cleanErr != nil {
			return fmt.Errorf("failed to clean response JSON: %w", cleanErr)
		}
		interaction.Response = cleanedResp
	}

	r.mu.Lock()
	r.cassette.Interactions = append(r.cassette.Interactions, interaction)
	saveErr := r.saveCassette()
	r.mu.Unlock()

	if saveErr != nil {
		return fmt.Errorf("failed to save cassette: %w", saveErr)
	}

	return err
}

// ClientConn wraps a grpc.ClientConnInterface to intercept calls.
type ClientConn struct {
	underlying grpc.ClientConnInterface
	recorder   *Recorder
}

// NewClientConn creates a new ClientConn wrapping the underlying connection.
func NewClientConn(underlying grpc.ClientConnInterface, recorder *Recorder) *ClientConn {
	return &ClientConn{
		underlying: underlying,
		recorder:   recorder,
	}
}

// Invoke intercepts unary RPC calls.
func (c *ClientConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	return c.recorder.Intercept(ctx, method, args, reply, func() error {
		if c.underlying == nil {
			return status.Error(codes.Internal, "gRPC VCR: no underlying connection in ReplayOnly mode")
		}

		return c.underlying.Invoke(ctx, method, args, reply, opts...)
	})
}

// NewStream intercepts streaming RPC calls and always returns unimplemented error since streaming is not supported.
func (c *ClientConn) NewStream(_ context.Context, _ *grpc.StreamDesc, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "gRPC VCR: streaming RPCs are not supported")
}

// Close closes the underlying connection if it implements io.Closer.
func (c *ClientConn) Close() error {
	if c.underlying == nil {
		return nil
	}

	if closer, ok := c.underlying.(interface{ Close() error }); ok {
		return closer.Close()
	}

	return nil
}

func cleanJSON(jsonStr string) (string, error) {
	var val any
	if err := json.Unmarshal([]byte(jsonStr), &val); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(val, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
