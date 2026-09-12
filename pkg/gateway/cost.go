package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/fregie/tokenhush/pkg/extension"
)

// maxCostStreamCapture 限制成本记录器为流式（SSE）响应保留的最大字节数。
// usage 只在流的后段出现，因此记录器保留尾部、超出上限时丢弃最旧的数据，
// 使长时间存活的流不会无限占用内存。非流式响应已由 pipeline 整体缓冲，
// 这里按原样完整保留。
const maxCostStreamCapture = 1 << 20 // 1 MiB

// costRecorder 是一个给 CostSink 留存上游响应副本的 http.ResponseWriter。
// 它绝不改变客户端收到的内容：每个字节都原样转发，Flush 也如实透传，
// 因此 SSE 帧仍然即时下发。它捕获的是 pipeline 入站回填之前的响应，
// 所以“为客户端还原出来的原文 secret”永远不会交给成本接收器。
type costRecorder struct {
	dst       http.ResponseWriter
	status    int
	header    http.Header
	body      []byte
	streaming bool
	wroteHead bool
}

// Header 实现 http.ResponseWriter。
func (r *costRecorder) Header() http.Header { return r.dst.Header() }

// WriteHeader 实现 http.ResponseWriter。它记录状态码并快照响应头，
// 然后只向下游转发一次。
func (r *costRecorder) WriteHeader(status int) {
	if r.wroteHead {
		return
	}
	r.wroteHead = true
	r.status = status
	r.header = r.dst.Header().Clone()
	r.streaming = isEventStreamHeader(r.header)
	r.dst.WriteHeader(status)
}

// Write 实现 http.ResponseWriter：留存一份副本后原样转发。
func (r *costRecorder) Write(p []byte) (int, error) {
	if !r.wroteHead {
		r.WriteHeader(http.StatusOK)
	}
	r.capture(p)
	return r.dst.Write(p)
}

// Flush 实现 http.Flusher，使 forwarder 的 ResponseController 无需等待
// 记录器即可把 SSE 帧推给客户端。
func (r *costRecorder) Flush() {
	if flusher, ok := r.dst.(http.Flusher); ok {
		flusher.Flush()
	}
}

// capture 把 p 追加到记录器的副本。流式响应只保留最近的
// maxCostStreamCapture 字节；非流式响应本来就被 pipeline 整体缓冲。
func (r *costRecorder) capture(p []byte) {
	r.body = append(r.body, p...)
	if r.streaming && len(r.body) > maxCostStreamCapture {
		r.body = append(r.body[:0:0], r.body[len(r.body)-maxCostStreamCapture:]...)
	}
}

// response 构造交给 CostSink 的 extension.Response。响应体被解析为 JSON；
// 一条 SSE 流则变成其 data 事件的解码列表。无法解析的载荷（或没有任何
// data 事件的 SSE 流）得到 nil JSON，接收器据此记一行“usage unavailable”。
func (r *costRecorder) response() *extension.Response {
	resp := &extension.Response{Status: r.status, Headers: r.header}
	if r.streaming {
		resp.JSON = parseSSEEvents(r.body)
		return resp
	}
	if len(r.body) == 0 {
		return resp
	}
	var decoded any
	if err := json.Unmarshal(r.body, &decoded); err == nil {
		resp.JSON = decoded
	}
	return resp
}

// parseSSEEvents 解析原始 SSE 文本，把每个 data: 载荷 JSON 解码后按顺序
// 收集。空载荷与 [DONE] 哨兵被跳过；没有任何可解码事件时返回 nil。
func parseSSEEvents(raw []byte) any {
	var events []any
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var event any
		if err := json.Unmarshal([]byte(payload), &event); err == nil {
			events = append(events, event)
		}
	}
	if len(events) == 0 {
		return nil
	}
	return events
}

// parseRequestJSON 解码已脱敏的请求体，供接收器做模型名兜底。非 JSON 文档
// 返回 nil：cost 接缝只接受解析后的 JSON，从不接收原始字节。
func parseRequestJSON(body []byte) any {
	if len(body) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil
	}
	return decoded
}

// isEventStreamHeader 判断响应 Content-Type 是否为 SSE，忽略参数与大小写。
func isEventStreamHeader(header http.Header) bool {
	mediaType := strings.TrimSpace(header.Get("Content-Type"))
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = mediaType[:i]
	}
	return strings.EqualFold(strings.TrimSpace(mediaType), "text/event-stream")
}
