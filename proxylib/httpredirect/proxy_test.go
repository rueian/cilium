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

// +build !privileged_tests

package httpredirect

import (
	"testing"

	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"

	// log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	// log.SetLevel(log.DebugLevel)

	TestingT(t)
}

type HTTPRedirectSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&HTTPRedirectSuite{})

// Set up access log server and Library instance for all the test cases
func (s *HTTPRedirectSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *HTTPRedirectSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *HTTPRedirectSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *HTTPRedirectSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

func (s *HTTPRedirectSuite) TestHTTPRedirectOnDataIncomplete(c *C) {
	conn := s.ins.CheckNewConnectionOK(c, "HTTPRedirect", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "no-policy")
	msg := "GET /hello HTTP/1.1\r\n"
	msg += "Host: localhost\r\n"
	msg += "User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\r\n"
	msg += "Connection: Keep-Alive\r\n"
	data := [][]byte{[]byte(msg)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 1)
}

func (s *HTTPRedirectSuite) TestHTTPRedirectOnDataBasicPass(c *C) {
	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "HTTPRedirect"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "ProxyAddr"
		      value: "repeater"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "HTTPRedirect", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	msg := "POST /hello HTTP/1.1\r\n"
	msg += "Host: localhost\r\n"
	msg += "User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\r\n"
	msg += "Connection: Keep-Alive\r\n"
	msg += "Content-Length: 9\r\n"
	msg += "\r\n"
	msg += "123456789"
	data := [][]byte{[]byte(msg)}
	conn.CheckOnDataOK(c, false, false, &data, RepeaterHello,
		proxylib.DROP, len(msg)-9,
		proxylib.DROP, 9)
}

func (s *HTTPRedirectSuite) TestHTTPRedirectOnDataMultipleReq(c *C) {

	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "HTTPRedirect"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "ProxyAddr"
		      value: "repeater"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "HTTPRedirect", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	msg1 := "GET /hello HTTP/1.1\r\n"
	msg1 += "Host: localhost\r\n"
	msg1 += "User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\r\n"
	msg1 += "Connection: Keep-Alive\r\n"
	msg1 += "\r\n"
	data := [][]byte{[]byte(msg1), []byte(msg1)}
	conn.CheckOnDataOK(c, false, false, &data, append(RepeaterHello, RepeaterHello...),
		proxylib.DROP, len(msg1),
		proxylib.DROP, len(msg1))
}

func (s *HTTPRedirectSuite) TestHTTPRedirectOnDataAllowDenyCmd(c *C) {

	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp2"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "HTTPRedirect"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "ProxyAddr"
		      value: "repeater"
			>
			rule: <
			  key: "Methods"
		      value: "GET"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "HTTPRedirect", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp2")
	msg1 := "GET /hello HTTP/1.1\r\n"
	msg1 += "Host: localhost\r\n"
	msg1 += "User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\r\n"
	msg1 += "Connection: Keep-Alive\r\n"
	msg1 += "\r\n"
	msg2 := "OPTIONS /hello HTTP/1.1\r\n"
	msg2 += "Host: localhost\r\n"
	msg2 += "User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\r\n"
	msg2 += "Connection: Keep-Alive\r\n"
	msg2 += "\r\n"
	data := [][]byte{[]byte(msg1 + msg2)}
	conn.CheckOnDataOK(c, false, false, &data, RepeaterHello,
		proxylib.DROP, len(msg1),
		proxylib.PASS, len(msg2))
}

func (s *HTTPRedirectSuite) TestHTTPRedirectOnDataAllowDenyRegex(c *C) {

	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp3"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "HTTPRedirect"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "ProxyAddr"
		      value: "repeater"
			>
			rule: <
			  key: "PathRegex"
		      value: "/he.*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "HTTPRedirect", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp3")
	msg1 := "GET /hello HTTP/1.1\r\n"
	msg1 += "Host: localhost\r\n"
	msg1 += "User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\r\n"
	msg1 += "Connection: Keep-Alive\r\n"
	msg1 += "\r\n"
	msg2 := "GET /olleh HTTP/1.1\r\n"
	msg2 += "Host: localhost\r\n"
	msg2 += "User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\r\n"
	msg2 += "Connection: Keep-Alive\r\n"
	msg2 += "\r\n"
	data := [][]byte{[]byte(msg1 + msg2)}
	conn.CheckOnDataOK(c, false, false, &data, RepeaterHello,
		proxylib.DROP, len(msg1),
		proxylib.PASS, len(msg2))
}
