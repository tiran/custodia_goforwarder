package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/sndnvaps/selinux"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
)

var (
	upstream   = flag.String("upstream", "https://localhost:14443/secrets", "upstream server")
	certFile   = flag.String("cert", "client.cert", "A PEM eoncoded certificate file.")
	keyFile    = flag.String("key", "client.key", "A PEM encoded private key file.")
	caFile     = flag.String("cacert", "ca.pem", "A PEM eoncoded CA's certificate file.")
	socketFile = flag.String("socketfile", "./forwarder.sock", "Unix Socket File")
)

type Forwarder struct {
	Upstream  *url.URL
	Transport *http.Transport
}

func NewForwarder(certFile string, keyFile string, caFile string, upstream string) (*Forwarder, error) {
	url, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}

	return &Forwarder{Upstream: url, Transport: transport}, nil
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func (forwarder *Forwarder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	/* copied from reverseproxy.go ServeHTTP()
	proxy := httputil.NewSingleHostReverseProxy(forwarder.Upstream)
	proxy.Transport = forwarder.Transport
	proxy.ServeHTTP(w, req)
	return
	*/
	log.Println(req)

	outreq := new(http.Request)
	*outreq = *req // includes shallow copies of maps, but okay
	outreq.URL.Scheme = forwarder.Upstream.Scheme
	outreq.URL.Host = forwarder.Upstream.Host
	outreq.URL.Path = singleJoiningSlash(forwarder.Upstream.Path, req.URL.Path)
	outreq.Proto = "HTTP/1.1"
	outreq.ProtoMajor = 1
	outreq.ProtoMinor = 1
	outreq.Close = false
	outreq.Header.Set("CUSTODIA_CERT_AUTH", "true")

	/* Go doesn't let me get to the FD of a connection unless I hijack it */
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	ucred, label, err := getPeerInfo(conn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	peercred := fmt.Sprintf("%d:%d:%d", ucred.Pid, ucred.Uid, ucred.Gid)
	outreq.Header.Set("CUSTODIA_PEER_CRED", peercred)
	outreq.Header.Set("CUSTODIA_PEER_LABEL", label)
	// outreq.Header.Set("REMOTE_USER", peercred)

	res, err := forwarder.Transport.RoundTrip(outreq)
	if err != nil {
		log.Println("http: proxy error: ", err)
		outresp := &http.Response{
			Status:        "",
			StatusCode:    http.StatusInternalServerError,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Request:       outreq,
			ContentLength: 0,
			Close:         true,
		}
		outresp.Header.Set("Content-Type", "text/plain; charset=utf-8")
		outresp.Header.Set("CUSTODIA_PEER_CRED", peercred)
		outresp.Header.Set("CUSTODIA_PEER_LABEL", label)
		outresp.Write(bufrw)
		bufrw.Flush()
		log.Println(outresp)
		// log.Println(err)
		return
	}
	outresp := new(http.Response)
	*outresp = *res
	outresp.Header.Set("CUSTODIA_PEER_CRED", peercred)
	outresp.Header.Set("CUSTODIA_PEER_LABEL", label)
	outresp.Write(bufrw)
	bufrw.Flush()
}

func getPeerInfo(conn net.Conn) (ucred *syscall.Ucred, label string, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		err = errors.New("connection is not a Unix socket")
		return
	}

	file, err := unixConn.File() // dupped fd
	if err != nil {
		return
	}
	defer file.Close()

	fd := file.Fd()
	ucred, err = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return
	}
	label, err = selinux.Getpeercon(int(fd))
	if err != nil {
		return
	}
	return
}

func main() {
	flag.Parse()

	forwarder, err := NewForwarder(*certFile, *keyFile, *caFile, *upstream)
	if err != nil {
		log.Fatal(err)
	}

	if !strings.Contains(*socketFile, "/") {
		log.Fatal(errors.New("Server address is not a path"))
	}
	fi, err := os.Stat(*socketFile)
	if fi != nil && (fi.Mode()&os.ModeSocket) != 0 {
		os.Remove(*socketFile)
	}
	listener, err := net.Listen("unix", *socketFile)
	if err != nil {
		log.Fatal(err)
	}
	err = http.Serve(listener, forwarder)
	log.Fatal(err)
}
