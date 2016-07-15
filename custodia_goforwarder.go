package main

import (
	"bufio"
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
	"regexp"
	"strings"
	"syscall"
)

var (
	upstream   = flag.String("upstream", "https://localhost:14443/secrets", "upstream server")
	certFile   = flag.String("cert", "", "A PEM eoncoded certificate file.")
	keyFile    = flag.String("key", "", "A PEM encoded private key file.")
	caFile     = flag.String("cacert", "", "A PEM eoncoded CA's certificate file.")
	socketFile = flag.String("socketfile", "./forwarder.sock", "Unix Socket File")
)

var (
	dockerRegexp *regexp.Regexp
	rktRegexp    *regexp.Regexp
)

type Forwarder struct {
	Upstream  *url.URL
	Transport *http.Transport
}

func NewForwarder(upstream string) (*Forwarder, error) {
	log.Printf("Forwarding requests to %s", upstream)
	url, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{}
	return &Forwarder{Upstream: url, Transport: transport}, nil
}

func (forwarder *Forwarder) SetCACert(caFile string) error {
	log.Printf("Loading CA file %s", caFile)
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return err
	}
	if forwarder.Transport.TLSClientConfig == nil {
		forwarder.Transport.TLSClientConfig = &tls.Config{}
	}

	tlsConfig := forwarder.Transport.TLSClientConfig
	if tlsConfig.RootCAs == nil {
		tlsConfig.RootCAs = x509.NewCertPool()
	}
	ok := tlsConfig.RootCAs.AppendCertsFromPEM(caCert)
	if !ok {
		return errors.New("Failed to load CA cert")
	}
	return nil
}

func (forwarder *Forwarder) SetClientCert(certFile, keyFile string) error {
	log.Printf("Loading client cert %s : %s", certFile, keyFile)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	if forwarder.Transport.TLSClientConfig == nil {
		forwarder.Transport.TLSClientConfig = &tls.Config{}
	}
	tlsConfig := forwarder.Transport.TLSClientConfig
	tlsConfig.Certificates = []tls.Certificate{cert}
	tlsConfig.BuildNameToCertificate()
	return nil
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
	ctyp, cid, err := getContainerId(int(ucred.Pid))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	peercred := fmt.Sprintf("%d:%d:%d", ucred.Pid, ucred.Uid, ucred.Gid)
	outreq.Header.Set("CUSTODIA_PEER_CRED", peercred)
	outreq.Header.Set("CUSTODIA_PEER_LABEL", label)
	outreq.Header.Set("CUSTODIA_CONTAINER_TYPE", ctyp)
	outreq.Header.Set("CUSTODIA_CONTAINER_ID", cid)
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
		outresp.Header.Set("CUSTODIA_CONTAINER_TYPE", ctyp)
		outresp.Header.Set("CUSTODIA_CONTAINER_ID", cid)
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
	outresp.Header.Set("CUSTODIA_CONTAINER_TYPE", ctyp)
	outresp.Header.Set("CUSTODIA_CONTAINER_ID", cid)
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

func getContainerId(pid int) (typ string, id string, err error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var line string
		var rs []string
		line = scanner.Text()
		rs = dockerRegexp.FindStringSubmatch(line)
		if len(rs) == 2 {
			return "docker", rs[1], nil
		}
		rs = rktRegexp.FindStringSubmatch(line)
		if len(rs) == 2 {
			id = strings.Replace(rs[1], "\x2d", "-", -1)
			return "rkt", id, nil
		}
	}
	return "", "", nil
}

func main() {
	flag.Parse()

	forwarder, err := NewForwarder(*upstream)
	if err != nil {
		log.Fatal(err)
	}
	if *caFile != "" {
		err = forwarder.SetCACert(*caFile)
		if err != nil {
			log.Fatal(err)
		}
	}
	if *certFile != "" {
		err = forwarder.SetClientCert(*certFile, *keyFile)
		if err != nil {
			log.Fatal(err)
		}
	}

	dockerRegexp = regexp.MustCompile(`/docker-([0-9a-f]{64})\.scope`)
	rktRegexp = regexp.MustCompile(`/machine-rkt\\x2([\\x0-9a-f]+)\.scope`)

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
	log.Printf("Listening on %s", *socketFile)
	err = http.Serve(listener, forwarder)
	log.Fatal(err)
}
