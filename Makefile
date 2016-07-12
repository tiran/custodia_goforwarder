PROJECT=custodia_goforwarder

VENV=venv
PYTHON=python3
CUSTODIA=${VENV}/bin/custodia
REQUIREMENTS=./custodia
CA_DIR=${CURDIR}/custodia/tests/ca
SERVER_DIR=${CURDIR}/srv

# CURL_CMD=curl --unix-socket server_socket -H "REMOTE_USER: user"
CURL_CUSTODIA_CMD=curl --cacert ${CA_DIR}/custodia-ca.pem \
	--cert ${CA_DIR}/custodia-client.pem \
	--key ${CA_DIR}/custodia-client.key \
	-H "CUSTODIA_CERT_AUTH: true"
CURL_FORWARDER_CMD=curl -v --unix-socket ./forwarder.sock http://localhost/tests/mysecret

all: ${CUSTODIA} ${PROJECT}

${VENV}:
	virtualenv --python=${PYTHON} ${VENV}
	${VENV}/bin/pip install --upgrade pip setuptools

${CUSTODIA}: | ${VENV}
	${VENV}/bin/pip install ${REQUIREMENTS}

${PROJECT}: ${PROJECT}.go
	go fmt $<
	go build $<

.PHONY=request
request:
	${CURL_FORWARDER_CMD}

.PHONY=run_goforwarder
run_goforwarder: ${PROJECT}
	./${PROJECT} \
	    -cacert ${CA_DIR}/custodia-ca.pem \
	    -cert ${CA_DIR}/custodia-client.pem \
	    -key ${CA_DIR}/custodia-client.key

.PHONY=run_custodia
run_custodia: ${CUSTODIA}
	CA_DIR=${CA_DIR} SERVER_DIR=${SERVER_DIR} ${CUSTODIA} srv/custodia.conf

.PHONY=init_secret
init_secret:
	${CURL_CUSTODIA_CMD} -X POST https://localhost:14443/secrets/tests/
	${CURL_CUSTODIA_CMD} -H "Content-Type: application/json" \
	    -X PUT \
	    -d '{"type": "simple", "value": "SuperSecretPassword"}' \
	    https://localhost:14443/secrets/tests/mysecret

.PHONY=upgrade
upgrade: | ${VENV}
	${VENV}/bin/pip install --upgrade ${REQUIREMENTS}

.PHONY=clean
clean:
	@rm -rf ${VENV}
	@rm -rf srv/secrets.db
	@rm -f srv/audit.log
	@rm -f ${PROJECT}
	@rm -f forwarder.sock
