// Copyright 2018 Authors of Cilium
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

package httpredirect

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/cilium/proxylib/proxylib"

	cilium "github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
)

type httpRedirect struct {
	ProxyAddr   string
	HeaderKey   string
	HeaderValue string
	Methods     string
	PathRegex   *regexp.Regexp
}

type httpHead struct {
	Proto     string
	Method    string
	URI       string
	Header    textproto.MIMEHeader
	ProxyAddr string
}

func (rule *httpRedirect) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'
	req, ok := data.(*httpHead)
	if !ok {
		log.Warning("Matches() called with type other than *httpHead")
		return false
	}

	if rule.Methods != "" && !strings.Contains(rule.Methods, req.Method) {
		return false
	}

	if rule.HeaderKey != "" {
		for _, v := range req.Header.Values(rule.HeaderKey) {
			if v == rule.HeaderValue {
				goto regex
			}
		}
		return false
	}
regex:
	if rule.PathRegex != nil && !rule.PathRegex.MatchString(req.URI) {
		return false
	}

	req.ProxyAddr = rule.ProxyAddr
	return true
}

// ruleParser parses protobuf L7 rules to enforcement objects
// May panic
func ruleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return nil
	}

	allowRules := l7Rules.GetL7AllowRules()
	rules := make([]proxylib.L7NetworkPolicyRule, 0, len(allowRules))
	for _, l7Rule := range allowRules {
		var rr httpRedirect
		for k, v := range l7Rule.Rule {
			switch k {
			case "ProxyAddr":
				rr.ProxyAddr = v
			case "HeaderKey":
				rr.HeaderKey = v
			case "HeaderValue":
				rr.HeaderValue = v
			case "Methods":
				rr.Methods = v
			case "PathRegex":
				if v != "" {
					rr.PathRegex = regexp.MustCompile(v)
				}
			default:
				proxylib.ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if rr.ProxyAddr == "" {
			proxylib.ParseError("ProxyAddr should not be empty", rule)
		}
		rules = append(rules, &rr)
	}
	return rules
}

type factory struct{}

func init() {
	log.Debug("init(): Registering HTTPRedirectParserFactory")
	proxylib.RegisterParserFactory("HTTPRedirect", &factory{})
	proxylib.RegisterL7RuleParser("HTTPRedirect", ruleParser)
}

type Decision int

const (
	DecisionNotYet = iota
	DecisionPass
	DecisionProxy
	DecisionRedirect
)

type parser struct {
	connection *proxylib.Connection
	decision   Decision
	remaining  int // -1 for transfer-encoding

	proxyAddr string
	proxyConn io.ReadWriteCloser
}

func (f *factory) Create(connection *proxylib.Connection) interface{} {
	log.Debugf("HTTPRedirectParserFactory: Create: %v", connection)

	return &parser{connection: connection}
}

func parseHead(data []byte) (*httpHead, error) {
	tp := textproto.NewReader(bufio.NewReader(bytes.NewBuffer(data)))
	line, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return nil, fmt.Errorf("broken http request with first line: %s", line)
	}
	s2 += s1 + 1

	headers, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}

	return &httpHead{
		Method: line[:s1],
		URI:    line[s1+1 : s2],
		Proto:  line[s2+1:],
		Header: headers,
	}, nil
}

func (p *parser) OnData(reply, endStream bool, dataArray [][]byte) (proxylib.OpType, int) {
	defer func() {
		if endStream && p.proxyConn != nil {
			p.proxyConn.Close()
		}
	}()

	if p.decision == DecisionNotYet {
		// inefficient, but simple
		data := bytes.Join(dataArray, []byte{})

		// read the request/response header to make decision
		headLen := bytes.Index(data, []byte("\r\n\r\n"))
		if headLen < 0 {
			return proxylib.MORE, 1
		}
		headLen += 4 // include the \r\n\r\n

		head, err := parseHead(data[:headLen])
		if err != nil {
			return proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_TYPE)
		}

		contentLength, _ := strconv.Atoi(head.Header.Get("Content-Length"))
		transferEncoding := len(head.Header.Get("Transfer-Encoding")) > 0
		upgrade := len(head.Header.Get("Upgrade")) > 0

		if transferEncoding {
			p.remaining = -1
		} else {
			p.remaining = contentLength
		}

		if upgrade || head.Method == "CONNECT" {
			p.decision = DecisionProxy
			return proxylib.PASS, headLen
		} else if reply || !p.connection.Matches(head) {
			p.decision = DecisionPass
			return proxylib.PASS, headLen
		} else {
			p.proxyAddr = head.ProxyAddr // hack: insert ProxyAddr after Matches
			p.decision = DecisionRedirect
			log.Debugf("HTTPRedirect DecisionRedirect %d", headLen)
			if err := p.proxyWrite(data[:headLen]); err != nil {
				log.Debugf("HTTPRedirect proxyWrite err %v", err)
				return proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_TYPE)
			}
			if p.remaining == 0 {
				resp, err := p.proxyRead()
				if err != nil {
					log.Debugf("HTTPRedirect proxyRead err %v", err)
					return proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_TYPE)
				}
				p.connection.Inject(true, resp)
				p.decision = DecisionNotYet // reset
			}
			return proxylib.DROP, headLen
		}
	}

	// decision is made

	if p.decision == DecisionProxy {
		return proxylib.PASS, len(bytes.Join(dataArray, []byte{}))
	}

	if p.decision == DecisionPass {
		if p.remaining >= 0 {
			p.decision = DecisionNotYet // reset
			return proxylib.PASS, p.remaining
		} else {
			// transfer-encoding

			// inefficient, but simple
			chunkLen := bytes.Index(bytes.Join(dataArray, []byte{}), []byte("\r\n"))
			if chunkLen < 0 {
				return proxylib.MORE, 1
			}
			if chunkLen == 0 {
				p.decision = DecisionNotYet // reset
			}
			return proxylib.PASS, chunkLen + 2
		}
	}

	// decision proxy body
	// p.decision == DecisionProxy

	// inefficient, but simple
	data := bytes.Join(dataArray, []byte{})

	if p.remaining >= 0 {
		if ld := len(data); ld < p.remaining {
			return proxylib.MORE, p.remaining - ld
		}
		if err := p.proxyWrite(data[:p.remaining]); err != nil {
			return proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_TYPE)
		}
		resp, err := p.proxyRead()
		if err != nil {
			return proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_TYPE)
		}
		p.connection.Inject(true, resp)
		p.decision = DecisionNotYet // reset
		return proxylib.DROP, p.remaining
	} else {
		// transfer-encoding
		chunkLen := bytes.Index(data, []byte("\r\n"))
		if chunkLen < 0 {
			return proxylib.MORE, 1
		}
		if err := p.proxyWrite(data[:chunkLen+2]); err != nil {
			return proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_TYPE)
		}
		if chunkLen == 0 {
			resp, err := p.proxyRead()
			if err != nil {
				return proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_TYPE)
			}
			p.connection.Inject(true, resp)
			p.decision = DecisionNotYet // reset
		}
		return proxylib.DROP, chunkLen + 2
	}
}

func (p *parser) proxyWrite(data []byte) (err error) {
	if p.proxyConn == nil {
		if p.proxyAddr == "repeater" {
			p.proxyConn = NewRepeater()
		} else {
			if p.proxyConn, err = net.Dial("tcp", p.proxyAddr); err != nil {
				return err
			}
		}
	}
	_, err = p.proxyConn.Write(data)
	return err
}

func (p *parser) proxyRead() (data []byte, err error) {
	rb := bufio.NewReader(p.proxyConn)
	tp := textproto.NewReader(rb)
	line, err := tp.ReadLineBytes()
	if err != nil {
		return nil, err
	}
	header, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	contentLength, _ := strconv.Atoi(header.Get("Content-Length"))
	transferEncoding := len(header.Get("Transfer-Encoding")) > 0

	wb := bytes.NewBuffer(nil)
	wb.Write(line)
	wb.Write([]byte("\r\n"))
	for k, vs := range header {
		for _, v := range vs {
			wb.Write([]byte(k + ": " + v + "\r\n"))
		}
	}
	wb.Write([]byte("\r\n"))

	if transferEncoding {
		for len(line) != 0 {
			line, err = tp.ReadLineBytes()
			if err != nil {
				return nil, err
			}
			wb.Write(line)
			wb.Write([]byte("\r\n"))
		}
	} else {
		body := make([]byte, contentLength)
		if _, err = io.ReadFull(rb, body); err != nil {
			return nil, err
		}
		wb.Write(body)
	}
	return wb.Bytes(), nil
}
