package grpcvcr

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.yaml.in/yaml/v4"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

type mockClientConn struct {
	invokeCalled bool
	invokeFn     func(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error
}

func (m *mockClientConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	m.invokeCalled = true
	if m.invokeFn != nil {
		return m.invokeFn(ctx, method, args, reply, opts...)
	}

	return nil
}

func (m *mockClientConn) NewStream(_ context.Context, _ *grpc.StreamDesc, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "mock: stream unimplemented")
}

func TestRecorder_Passthrough(t *testing.T) {
	t.Parallel()

	mock := &mockClientConn{
		invokeFn: func(_ context.Context, _ string, _, reply any, _ ...grpc.CallOption) error {
			resp := reply.(*structpb.Struct)
			resp.Fields = map[string]*structpb.Value{
				"reason": structpb.NewStringValue("passthrough_called"),
			}

			return nil
		},
	}

	tmpDir := t.TempDir()
	cassettePath := filepath.Join(tmpDir, "test.yaml")

	rec, err := NewRecorder(cassettePath, ModePassthrough, t.Name())
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	conn := NewClientConn(mock, rec)
	req, _ := structpb.NewStruct(map[string]any{"expiry_date": "2026-01-01"})
	resp := &structpb.Struct{}

	err = conn.Invoke(context.Background(), "test_method", req, resp)
	if err != nil {
		t.Fatalf("Invoke failed: %v", err)
	}

	if !mock.invokeCalled {
		t.Error("underlying connection was not called in Passthrough mode")
	}

	if resp.GetFields()["reason"].GetStringValue() != "passthrough_called" {
		t.Errorf("unexpected response: %v", resp)
	}

	if _, err := os.Stat(cassettePath); !os.IsNotExist(err) {
		t.Error("cassette file should not be created in Passthrough mode")
	}
}

func TestRecorder_RecordAndReplay(t *testing.T) {
	t.Parallel()

	methodName := "test_method"

	// 1. RECORD MODE
	t.Run("Record", func(t *testing.T) {
		t.Parallel()

		cassettePath := filepath.Join(t.TempDir(), "test.yaml")
		mock := &mockClientConn{
			invokeFn: func(_ context.Context, _ string, _, reply any, _ ...grpc.CallOption) error {
				resp := reply.(*structpb.Struct)
				resp.Fields = map[string]*structpb.Value{
					"reason": structpb.NewStringValue("recorded_reason"),
				}

				return nil
			},
		}

		rec, err := NewRecorder(cassettePath, ModeRecordOnly, t.Name())
		if err != nil {
			t.Fatalf("failed to create recorder: %v", err)
		}

		conn := NewClientConn(mock, rec)
		req, _ := structpb.NewStruct(map[string]any{"expiry_date": "2026-01-01"})
		resp := &structpb.Struct{}

		err = conn.Invoke(context.Background(), methodName, req, resp)
		if err != nil {
			t.Fatalf("Invoke failed: %v", err)
		}

		if !mock.invokeCalled {
			t.Error("underlying connection was not called")
		}

		if resp.GetFields()["reason"].GetStringValue() != "recorded_reason" {
			t.Errorf("unexpected response: %v", resp)
		}

		if err := conn.Close(); err != nil {
			t.Fatalf("failed to close connection: %v", err)
		}

		// Verify cassette was written
		if _, err := os.Stat(cassettePath); os.IsNotExist(err) {
			t.Fatal("cassette file was not created")
		}
	})

	// 2. REPLAY MODE (Strict Match)
	t.Run("ReplayMatch", func(t *testing.T) {
		t.Parallel()

		cassettePath := filepath.Join(t.TempDir(), "test.yaml")
		writeTestCassette(t, cassettePath, methodName,
			`{"expiry_date": "2026-01-01"}`,
			`{"reason": "recorded_reason"}`, nil)

		// Mock should NOT be called in replay mode
		mock := &mockClientConn{
			invokeFn: func(_ context.Context, _ string, _, _ any, _ ...grpc.CallOption) error {
				t.Fatal("underlying connection should not be called during replay")

				return nil
			},
		}

		rec, err := NewRecorder(cassettePath, ModeReplayOnly, t.Name())
		if err != nil {
			t.Fatalf("failed to create recorder: %v", err)
		}

		conn := NewClientConn(mock, rec)
		req, _ := structpb.NewStruct(map[string]any{"expiry_date": "2026-01-01"})
		resp := &structpb.Struct{}

		err = conn.Invoke(context.Background(), methodName, req, resp)
		if err != nil {
			t.Fatalf("Replay Invoke failed: %v", err)
		}

		if mock.invokeCalled {
			t.Error("underlying connection was called during replay")
		}

		expectedResp, _ := structpb.NewStruct(map[string]any{"reason": "recorded_reason"})
		if diff := cmp.Diff(expectedResp, resp, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected response diff (-want +got):\n%s", diff)
		}
	})

	// 3. REPLAY MODE (Miss - Different Request)
	t.Run("ReplayMissDifferentRequest", func(t *testing.T) {
		t.Parallel()

		cassettePath := filepath.Join(t.TempDir(), "test.yaml")
		writeTestCassette(t, cassettePath, methodName,
			`{"expiry_date": "2026-01-01"}`,
			`{"reason": "recorded_reason"}`, nil)

		mock := &mockClientConn{}
		rec, err := NewRecorder(cassettePath, ModeReplayOnly, t.Name())
		if err != nil {
			t.Fatalf("failed to create recorder: %v", err)
		}

		conn := NewClientConn(mock, rec)
		// Different request value -> should miss
		req, _ := structpb.NewStruct(map[string]any{"expiry_date": "2027-01-01"})
		resp := &structpb.Struct{}

		err = conn.Invoke(context.Background(), methodName, req, resp)
		if err == nil {
			t.Fatal("expected error on replay miss, got nil")
		}

		if st, ok := status.FromError(err); !ok || st.Code() != codes.NotFound {
			t.Errorf("expected NotFound error, got %v", err)
		}
	})
}

func TestRecorder_RecordAndReplay_Error(t *testing.T) {
	t.Parallel()

	methodName := "test_method_error"

	// 1. RECORD ERROR
	t.Run("RecordError", func(t *testing.T) {
		t.Parallel()

		cassettePath := filepath.Join(t.TempDir(), "test.yaml")
		mock := &mockClientConn{
			invokeFn: func(_ context.Context, _ string, _, _ any, _ ...grpc.CallOption) error {
				return status.Error(codes.InvalidArgument, "invalid argument provided")
			},
		}

		rec, err := NewRecorder(cassettePath, ModeRecordOnly, t.Name())
		if err != nil {
			t.Fatalf("failed to create recorder: %v", err)
		}

		conn := NewClientConn(mock, rec)
		req, _ := structpb.NewStruct(map[string]any{"expiry_date": "invalid"})
		resp := &structpb.Struct{}

		err = conn.Invoke(context.Background(), methodName, req, resp)
		if err == nil {
			t.Fatal("expected error during Invoke, got nil")
		}

		if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument || st.Message() != "invalid argument provided" {
			t.Errorf("unexpected error returned: %v", err)
		}
	})

	// 2. REPLAY ERROR
	t.Run("ReplayError", func(t *testing.T) {
		t.Parallel()

		cassettePath := filepath.Join(t.TempDir(), "test.yaml")
		writeTestCassette(t, cassettePath, methodName,
			`{"expiry_date": "invalid"}`, "", &StatusError{
				Code:    uint32(codes.InvalidArgument),
				Message: "invalid argument provided",
			})

		mock := &mockClientConn{
			invokeFn: func(_ context.Context, _ string, _, _ any, _ ...grpc.CallOption) error {
				t.Fatal("underlying connection should not be called")

				return nil
			},
		}

		rec, err := NewRecorder(cassettePath, ModeReplayOnly, t.Name())
		if err != nil {
			t.Fatalf("failed to create recorder: %v", err)
		}

		conn := NewClientConn(mock, rec)
		req, _ := structpb.NewStruct(map[string]any{"expiry_date": "invalid"})
		resp := &structpb.Struct{}

		err = conn.Invoke(context.Background(), methodName, req, resp)
		if err == nil {
			t.Fatal("expected error on replay, got nil")
		}

		if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument || st.Message() != "invalid argument provided" {
			t.Errorf("unexpected replayed error: %v", err)
		}
	})
}

func writeTestCassette(t *testing.T, path string, method string, reqJSON string, respJSON string, errStatus *StatusError) {
	t.Helper()

	interaction := Interaction{
		Method:   method,
		Request:  reqJSON,
		Response: respJSON,
		Error:    errStatus,
	}

	cassette := Cassette{
		Interactions: []Interaction{interaction},
	}

	data, err := yaml.Marshal(cassette)
	if err != nil {
		t.Fatalf("failed to marshal test cassette: %v", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write test cassette: %v", err)
	}
}

func TestDefaultMatcher_SliceOrder(t *testing.T) {
	t.Parallel()

	// Construct two list values with same elements in different order
	val1, err := structpb.NewList([]any{
		map[string]any{"name": "package-a", "version": "1.0.0"},
		map[string]any{"name": "package-b", "version": "2.0.0"},
	})
	if err != nil {
		t.Fatalf("failed to create structpb.ListValue: %v", err)
	}

	val2, err := structpb.NewList([]any{
		map[string]any{"name": "package-b", "version": "2.0.0"},
		map[string]any{"name": "package-a", "version": "1.0.0"},
	})
	if err != nil {
		t.Fatalf("failed to create structpb.ListValue: %v", err)
	}

	// Marshal val2 to JSON (representing the recorded request)
	val2JSON, err := marshalOptions.Marshal(val2)
	if err != nil {
		t.Fatalf("failed to marshal structpb.ListValue: %v", err)
	}

	// DefaultMatcher should NOT match val1 against val2JSON because they contain the same elements
	// but in a different order (it is now order-sensitive).
	if DefaultMatcher("/test.Service/TestMethod", val1, string(val2JSON)) {
		t.Error("DefaultMatcher matched slice with different element order, but it should be order-sensitive")
	}

	// Verify it still fails if elements are actually different
	val3, err := structpb.NewList([]any{
		map[string]any{"name": "package-a", "version": "1.0.0"},
		map[string]any{"name": "package-c", "version": "3.0.0"},
	})
	if err != nil {
		t.Fatalf("failed to create structpb.ListValue: %v", err)
	}

	val3JSON, err := marshalOptions.Marshal(val3)
	if err != nil {
		t.Fatalf("failed to marshal structpb.ListValue: %v", err)
	}

	if DefaultMatcher("/test.Service/TestMethod", val1, string(val3JSON)) {
		t.Error("DefaultMatcher matched slices with different elements")
	}
}

func TestRecorder_Save_Sorted(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cassettePath := filepath.Join(tmpDir, "sorted_test.yaml")

	rec, err := NewRecorder(cassettePath, ModeRecordOnly, t.Name())
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	mock := &mockClientConn{}
	conn := NewClientConn(mock, rec)

	// Make calls in specific non-alphabetical order of method/requests
	// Call 1: method B, request Z
	// Call 2: method A, request Y
	// Call 3: method A, request X
	calls := []struct {
		method string
		reqVal string
	}{
		{"/test.Service/MethodB", "Z"},
		{"/test.Service/MethodA", "Y"},
		{"/test.Service/MethodA", "X"},
	}

	for _, call := range calls {
		req, _ := structpb.NewStruct(map[string]any{"expiry_date": call.reqVal})
		resp := &structpb.Struct{}
		err = conn.Invoke(context.Background(), call.method, req, resp)
		if err != nil {
			t.Fatalf("Invoke failed for %s (%s): %v", call.method, call.reqVal, err)
		}
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("failed to close connection: %v", err)
	}

	// Read the saved cassette and verify interactions are sorted
	data, err := os.ReadFile(cassettePath)
	if err != nil {
		t.Fatalf("failed to read cassette: %v", err)
	}

	var cass Cassette
	if err := yaml.Unmarshal(data, &cass); err != nil {
		t.Fatalf("failed to unmarshal cassette: %v", err)
	}

	if len(cass.Interactions) != 3 {
		t.Fatalf("expected exactly 3 interactions, got %d", len(cass.Interactions))
	}

	// Expected sorted order:
	// 1. MethodA, request X (since "X" < "Y")
	// 2. MethodA, request Y
	// 3. MethodB, request Z
	expectedOrder := []struct {
		method string
		reqVal string
	}{
		{"/test.Service/MethodA", "X"},
		{"/test.Service/MethodA", "Y"},
		{"/test.Service/MethodB", "Z"},
	}

	for i, expected := range expectedOrder {
		inter := cass.Interactions[i]
		if inter.Method != expected.method {
			t.Errorf("interaction %d: expected method %s, got %s", i, expected.method, inter.Method)
		}
		// Deserialise request to check the value
		reqMsg := &structpb.Struct{}
		if err := protojson.Unmarshal([]byte(inter.Request), reqMsg); err != nil {
			t.Fatalf("failed to unmarshal request in interaction %d: %v", i, err)
		}
		if reqMsg.GetFields()["expiry_date"].GetStringValue() != expected.reqVal {
			t.Errorf("interaction %d: expected request val %s, got %s", i, expected.reqVal, reqMsg.GetFields()["expiry_date"].GetStringValue())
		}
	}
}

func TestRecorder_Save_CleanJSON(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cassettePath := filepath.Join(tmpDir, "clean_test.yaml")

	rec, err := NewRecorder(cassettePath, ModeRecordOnly, t.Name())
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	mock := &mockClientConn{}
	conn := NewClientConn(mock, rec)

	req, _ := structpb.NewStruct(map[string]any{"expiry_date": "clean-me"})
	resp := &structpb.Struct{}

	err = conn.Invoke(context.Background(), "/test.Service/CleanMethod", req, resp)
	if err != nil {
		t.Fatalf("Invoke failed: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("failed to close connection: %v", err)
	}

	// Read the saved cassette
	data, err := os.ReadFile(cassettePath)
	if err != nil {
		t.Fatalf("failed to read cassette: %v", err)
	}

	var cass Cassette
	if err := yaml.Unmarshal(data, &cass); err != nil {
		t.Fatalf("failed to unmarshal cassette: %v", err)
	}

	if len(cass.Interactions) != 1 {
		t.Fatalf("expected exactly 1 interaction, got %d", len(cass.Interactions))
	}

	reqJSON := cass.Interactions[0].Request

	// Verify standard JSON formatting:
	// 1. One space after colon (e.g. `"expiryDate": "clean-me"`)
	// 2. Indent is two spaces (e.g. `  "expiryDate":`)
	// 3. No non-deterministic double spaces (which protojson sometimes generates)
	// Standard JSON output from json.MarshalIndent for our OSVConfig:
	// {
	//   "expiry_date": "clean-me"
	// }
	// Notice single space after colon!
	expectedJSON := "{\n  \"expiry_date\": \"clean-me\"\n}"
	if reqJSON != expectedJSON {
		t.Errorf("expected request JSON to be formatted as:\n%s\nbut got:\n%s", expectedJSON, reqJSON)
	}
}
