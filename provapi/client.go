package provapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// NewRequestID returns a random request ID.
func NewRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Call sends one request to the server listening on socketPath and returns
// its response. A response with OK=false is returned with its *Error; a
// service that cannot be reached is an *Error with CodeUnavailable.
func Call(ctx context.Context, socketPath string, req Request) (Response, error) {
	if _, err := req.Decode(); err != nil {
		return Response{}, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Response{}, &Error{Code: CodeUnavailable, Message: err.Error()}
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(time.Minute))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := WriteMessage(conn, req); err != nil {
		if errors.Is(err, ErrTooLarge) || ctx.Err() != nil {
			return Response{}, errors.Join(err, ctx.Err())
		}
		return Response{}, &Error{Code: CodeUnavailable, Message: "sending the request: " + err.Error()}
	}
	var resp Response
	if err := ReadMessage(bufio.NewReaderSize(conn, 16<<10), &resp); err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, &Error{Code: CodeUnavailable, Message: "reading the response: " + err.Error()}
	}
	if resp.ID != req.ID {
		return Response{}, errors.New("provapi: response for another request")
	}
	if !resp.OK {
		if resp.Error == nil {
			return resp, &Error{Code: CodeInternal, Message: "no error detail"}
		}
		return resp, resp.Error
	}
	return resp, nil
}

// DecodeResult decodes a successful response's result into v (strictly:
// unknown fields are an error).
func DecodeResult(resp Response, v any) error {
	dec := json.NewDecoder(bytes.NewReader(resp.Result))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("provapi: result: %w", err)
	}
	return nil
}

// ErrorCodeOf returns the code of an API error ("" for other errors).
func ErrorCodeOf(err error) ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
