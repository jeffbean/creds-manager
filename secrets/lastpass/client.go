package lastpass

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

type Client struct {
	httpClient *http.Client

	id                string
	keyIterationCount int
}

type Option func(*Client)

// NewClient returns a lastpass client
// to use this client you must first Login before performing any other actions
func NewClient(opts ...Option) (*Client, error) {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	client := &Client{
		httpClient: &http.Client{Jar: cookieJar},
	}

	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// Login logs in to the lastpass service - will fail if a session ID is already set.
func (c *Client) Login(username, password string) error {
	if c.id != "" {
		return fmt.Errorf("already logged in")
	}

	iterationCount, err := c.requestIterationCount(username)
	if err != nil {
		return err
	}

	res, err := c.httpClient.PostForm(
		fmt.Sprintf("%v/%v", LastPassBaseURI, "login.php"),
		url.Values{
			"method":     []string{"mobile"},
			"web":        []string{"1"},
			"xml":        []string{"1"},
			"username":   []string{username},
			"hash":       []string{string(makeHash(username, password, iterationCount))},
			"iterations": []string{fmt.Sprint(iterationCount)},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to post login request: %v", err)
	}

	defer res.Body.Close()
	var response struct {
		SessionID string `xml:"sessionid,attr"`
	}
	err = xml.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("failed to decode xml response: %v", err)
	}

	c.id = response.SessionID
	c.keyIterationCount = iterationCount

	return nil
}

// Logout logs your session out and will ensure we end the session
func (c *Client) Logout() error {
	u, err := url.Parse(fmt.Sprintf("%v/%v", LastPassBaseURI, "logout.php"))
	if err != nil {
		return err
	}
	values, err := url.ParseQuery("method=cli&noredirect=1")
	if err != nil {
		return err
	}
	u.RawQuery = values.Encode()

	if _, err := c.httpClient.Get(u.String()); err != nil {
		return err
	}

	return nil
}

// MakeEncryptionKey allows a client to get the encryption key without knowing your iteration number
// make it weird since the http client is what holds the iteration number, you could pass it in i guess.
func (c *Client) MakeEncryptionKey(username, password string) []byte {
	return makeKey(username, password, c.keyIterationCount)
}

// GetBlob fetches the lastpass blob and parses it into chunks. it does not open the blob
// and this is done in the Vault were we decrypt the chunks
func (c *Client) GetBlob(ctx context.Context) (*Blob, error) {
	rawBlob, err := c.fetchBlob(ctx)
	if err != nil {
		return nil, err
	}

	blob, err := parseBlob(bytes.NewReader(rawBlob))
	if err != nil {
		return nil, err
	}

	return blob, nil
}

func (c *Client) fetchBlob(ctx context.Context) ([]byte, error) {
	u, err := url.Parse(fmt.Sprintf("%v/%v", LastPassBaseURI, "getaccts.php"))
	if err != nil {
		return nil, err
	}
	u.RawQuery = (&url.Values{
		"mobile":    []string{"1"},
		"b64":       []string{"1"},
		"hash":      []string{"0.0"},
		"PHPSESSID": []string{c.id},
	}).Encode()

	res, err := c.httpClient.Get(u.String())
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(string(b))
}

func (c *Client) requestIterationCount(username string) (int, error) {
	u, err := url.Parse(fmt.Sprintf("%v/%v", LastPassBaseURI, "iterations.php"))
	if err != nil {
		return 0, err
	}

	res, err := c.httpClient.PostForm(u.String(), url.Values{"email": []string{username}})
	if err != nil {
		return 0, err
	}

	defer res.Body.Close()
	responseBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(string(responseBytes))
}

func makeKey(username, password string, iterationCount int) []byte {
	if iterationCount == 1 {
		b := sha256.Sum256([]byte(username + password))
		return b[:]
	}
	return pbkdf2.Key([]byte(password), []byte(username), iterationCount, 32, sha256.New)
}

func makeHash(username, password string, iterationCount int) []byte {
	key := makeKey(username, password, iterationCount)
	if iterationCount == 1 {
		b := sha256.Sum256([]byte(string(encodeHex(key)) + password))
		return encodeHex(b[:])
	}
	return encodeHex(pbkdf2.Key([]byte(key), []byte(password), 1, 32, sha256.New))
}

func encodeHex(b []byte) []byte {
	d := make([]byte, len(b)*2)
	n := hex.Encode(d, b)
	return d[:n]
}
